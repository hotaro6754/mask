# Deploying MaskGuard

MaskGuard has two deployment modes. They are deliberately hard to confuse: the production mode refuses to start on
any setting that would weaken a guarantee, and it lists every problem at once.

| | **Demo** (`docker-compose.yml`) | **Production** (`docker-compose.prod.yml`) |
|---|---|---|
| Data | Synthetic only, seeded automatically | Yours. Seeding is off and can't be switched on |
| `MASKGUARD_ENV` | `development` | `production` (any value other than these two is refused) |
| Identities | Demo users (`admin.ann` … with `<role>123`), one-click `/auth/demo` | Your user file only; demo users and `/auth/demo` refused |
| Secrets | Dev placeholders | Required, ≥ 32 characters, not copied from the examples |
| Database | PostgreSQL superuser, port 5432 published | Internal network, no published port, read-only gateway account |
| API | Plain HTTP on every interface | HTTPS (uvicorn's own TLS), published on `127.0.0.1` unless you choose otherwise |
| PostgreSQL proxy, Streamlit dashboard | Running | Not included; loopback-only if you run them yourself |

**The demo setup is not suitable for real customer data.** Anyone who can reach port 8000 can act as admin, and the
database port is open with a known password. Setting `MASKGUARD_ENV=production` on the demo Compose file makes
MaskGuard refuse to start rather than run it unsafely.

## Production quick start (reference stack)

```bash
cp deploy/production.env.example deploy/production.env      # git-ignored; fill in every value
python -c "import secrets; print(secrets.token_hex(32))"   # once per secret
# user store: copy deploy/users.example.yaml outside the repo, fill in hashes from `maskguard hash-password`
docker compose -f docker-compose.prod.yml --env-file deploy/production.env up -d --build
curl --cacert <your CA> https://127.0.0.1:8443/health
```

The stack:

1. **`db`** (PostgreSQL 16) runs on the internal `data` network with no published port. On first start,
   `deploy/postgres-init/10-gateway-role.sh` creates `maskguard_gateway`, a login that can only read the tables (and
   the tables the owner creates later). The owner account (`maskguard_owner`) owns the tables. Load your data with
   the owner account.
2. **`db-install`** is a one-shot job. It uses the **owner** URL to install or update MaskGuard's masking functions,
   then exits. The gateway never receives the owner password.
3. **`api`** connects as `maskguard_gateway`, serves HTTPS on 8443, and depends on `db-install` finishing
   successfully.

To use an existing database instead of the bundled one, run `maskguard db-install --db <owner URL>` against it
once, grant the gateway account read access (below), and point `MASKGUARD_DB` at it in a Compose override that
removes the `db` service.

## What production checks at startup

`maskguard serve` (and every other command that starts the engine) stops with exit code 4 and a list of problems
if any of these fail:

| Check | Refused when |
|---|---|
| Environment | `MASKGUARD_ENV` is anything but `development`/`production` (a typo like `prod` never means "demo on") |
| Demo mode | `MASKGUARD_DEMO` is not `0` |
| User store | `MASKGUARD_USERS` is unset, points at `policies/users.demo.yaml`, is missing, is empty, or contains any demo identity |
| Secrets | `MASKGUARD_JWT_SECRET` or `MASKGUARD_HMAC_KEY` is unset, shorter than 32 characters, or looks like an example (`change-me`, `dev-only`, `not-for-prod`, `example`, `placeholder`) |
| Database | `MASKGUARD_DB` isn't PostgreSQL or MySQL (SQLite has no accounts to restrict; there is no fallback to the demo database) |
| Seeding | `MASKGUARD_SEED_IF_EMPTY=1` (the default is `0` in production) |
| Masking functions | Missing, or not executable by the gateway account: run `maskguard db-install` with the owner account |
| Database account | PostgreSQL: superuser, `CREATEROLE`, `CREATEDB`, `BYPASSRLS` or `REPLICATION`; write (`INSERT`/`UPDATE`/`DELETE`/`TRUNCATE`/`TRIGGER`) on or ownership of any table; `CREATE` on schema `public` or the database; owning any `mg_*` masking function (it could redefine them); membership of `pg_write_all_data` or the server-file roles. MySQL: any privilege except `SELECT`, `EXECUTE`, `USAGE`, `SHOW VIEW` on the database (from `SHOW GRANTS`; column-level grants are fine), anything but `USAGE` on `*.*`, or inherited roles |
| Network | `serve` off loopback without `--ssl-certfile`/`--ssl-keyfile`; `proxy` or `dashboard --classic` off loopback at all |

**Noisy aggregates are refused in production** (decision D11 in `docs/design/PRIVACY_ACCOUNTING.md`). An analyst
query that would release a noisy SUM/AVG/COUNT is rejected before any budget is charged or data is read, and the
rejection is audited. Analysts keep every other masked view (HMAC tokens, redactions), and other uses of protected
numbers stay redacted. `maskguard status` shows "Noisy aggregates: disabled in production".

**Self-tests are refused in production.** The attack suite compares MaskGuard with naive output masking. To do
that it reads every protected column in full and sends crafted SQL straight to the database, bypassing the gateway.
The simulated insider attack signs in as a demo identity, and the dashboard benchmark runs its presets straight
against the database for a baseline. In production these are refused for every role:

| Entry point | Production result |
|---|---|
| `GET /attacks` (API, SDK, Control Room, `maskguard --api … attack`) | `403 {"detail": "self-tests are disabled in production"}` |
| `maskguard attack`, `maskguard test`, `maskguard simulate-attack` | `DENIED`, exit code 3, same message |
| Classic dashboard: attack suite, simulated attack, performance benchmark | Buttons replaced by a notice |

What the refusal guarantees:

- **The server enforces it**, inside the runners themselves (`attacks.require_self_test`), before the first query.
  The API, CLI and dashboard checks sit on top of that.
- **Nothing in the request can reopen it:** not the role, query parameters, or `MASKGUARD_DEMO`.
- **It fails closed.** Self-tests run only when `MASKGUARD_ENV` resolves to `development` now *and* the engine was
  built in development. An unrecognised value counts as production.
- **The refusal is audited.** The audit log records user, role (API and dashboard; the CLI refuses before it
  resolves an identity), channel and the reason. It never records SQL, schema or results.

Live check on PostgreSQL 16 under this profile: support and admin users each got 403 on every request, and the
tables' scan counters (`pg_stat_user_tables`) did not move, while an ordinary masked query moved them.

**Running the self-tests safely.** Use a development engine on synthetic or disposable data, never the production
database:

```bash
MASKGUARD_ENV=development MASKGUARD_DB=sqlite:///scratch/bank.db maskguard seed   # synthetic data
MASKGUARD_ENV=development MASKGUARD_DB=sqlite:///scratch/bank.db maskguard attack --role support
docker compose up        # or the demo stack: GET /attacks, dashboard tabs
```

To test a production policy, copy it into such an environment (`MASKGUARD_POLICY`) together with a synthetic
dataset that has the same schema.

`maskguard seed` is refused in production. Nothing in production writes to your database. The gateway's own state
(audit log, registry, integrity baseline) lives in `/app/data`.

## Environment variables (production)

| Variable | Required | Notes |
|---|---|---|
| `MASKGUARD_ENV` | yes | `production` |
| `MASKGUARD_DB` | yes | Gateway's read-only account, e.g. `postgresql://maskguard_gateway:<pw>@db:5432/bank`. Use URL-safe (hex) passwords |
| `MASKGUARD_USERS` | yes | Your user file (`users:` → `role`, `password_hash` from `maskguard hash-password`) |
| `MASKGUARD_JWT_SECRET` | yes | ≥ 32 chars; stable across restarts and identical on every instance |
| `MASKGUARD_HMAC_KEY` | yes | ≥ 32 chars; changing it changes every analyst token |
| `MASKGUARD_TLS_CERT`, `MASKGUARD_TLS_KEY` | when the API leaves loopback | PEM chain and key (or `--ssl-certfile`/`--ssl-keyfile`) |
| `MASKGUARD_DEMO`, `MASKGUARD_SEED_IF_EMPTY` | no | Must be `0` if set |
| `MASKGUARD_DB_ADMIN` | `db-install` only | Owner URL. Give it to the install job, never to the gateway |

The Compose file takes the same values from `deploy/production.env` (see `deploy/production.env.example`) and
refuses to render if any required one is empty: `docker compose config` fails with "required variable … is
missing a value".

## Database accounts

**PostgreSQL** (what the init script does):

```sql
CREATE ROLE maskguard_gateway LOGIN PASSWORD '…' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO maskguard_gateway;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO maskguard_gateway;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO maskguard_gateway;  -- run as the table owner
```

Then `maskguard db-install --db postgresql://<owner>@host/bank` installs `pgcrypto` and the `mg_*` functions.

**MySQL** (not part of the reference Compose stack; the restricted-account path is covered by
`tests/test_production.py::test_mysql_read_only_runtime_end_to_end` against MySQL 8.4):

```sql
CREATE USER 'maskguard_gateway'@'%' IDENTIFIED BY '…';
GRANT SELECT, EXECUTE ON bank.* TO 'maskguard_gateway'@'%';
```

`maskguard db-install --db mysql://<owner>@host/bank` creates the functions. The owner needs `CREATE ROUTINE`,
`ALTER ROUTINE` and, with binary logging on, `log_bin_trust_function_creators=1`.

## Network boundaries and TLS

- **API.** Uvicorn's built-in TLS (Python `ssl`). In production the API refuses to listen beyond loopback without
  a certificate and key. This was verified against the running stack with curl and with Python's `httpx` (strict
  X.509 checks). A client that trusts the CA gets 200; a client that doesn't is refused; plain HTTP to the port gets
  no response. The certificate must carry the usual CA/leaf extensions (CA: `basicConstraints`, `keyUsage`; leaf:
  `subjectAltName`, `extendedKeyUsage=serverAuth`, key identifiers): Python 3.13 rejects chains without them.
  Binding `127.0.0.1` behind a TLS-terminating reverse proxy on the same host is also allowed.
- **Published port.** `MASKGUARD_PUBLISH_ADDR` defaults to `127.0.0.1`. Set `0.0.0.0` only when the API must be
  reachable from other machines (it is HTTPS-only either way).
- **Database.** Internal Docker network (`internal: true`): no route to or from outside the project. Verified: no
  listener on host port 5432, and containers on other networks can't reach it.
- **PostgreSQL proxy: no TLS.** It declines `SSLRequest` and takes cleartext passwords. With a real `psql`:
  `sslmode=disable` and **`sslmode=prefer` (psql's default) connect in cleartext without warning**, and
  `sslmode=require` fails ("server does not support SSL"). Production therefore allows it on loopback only, and the
  reference stack doesn't run it. A generic TLS sidecar in front of it has **not** been tested with PostgreSQL's
  in-protocol SSL negotiation and should not be assumed to work.
- **Classic Streamlit dashboard.** Loopback only in production (its TLS settings are untested). The Control Room
  at `/ui/` is part of the API and inherits its TLS.

## Credentials

- Create users with `maskguard hash-password` (PBKDF2-SHA256, 200k iterations) into your own file. Roles must exist
  in the policy.
- Rotate `MASKGUARD_JWT_SECRET` to invalidate every session. Rotating `MASKGUARD_HMAC_KEY` changes every analyst
  token, so joins against old exports stop matching.
- Compose passes secrets as environment variables, so they're visible to anyone who can run `docker inspect` on the
  host. Treat the Docker host as inside the trust boundary, or move to Docker/Kubernetes secrets (see below).

## Remaining limitations

**Validation status.** The production profile has **not** been validated end to end with a fresh build of this
repository's `Dockerfile`. The environment it was developed in blocks the Dockerfile's `apt-get` step. The live
checks described above (TLS, authentication, database privileges, network isolation, refusals, and the demo stack
still working) ran on a stand-in image: an earlier build of the same Dockerfile with the Python dependencies
refreshed from `uv.lock` and the current source mounted in. Treat the profile as unvalidated until
`docker compose -f docker-compose.prod.yml build` succeeds and those checks pass on the resulting image.

These are not solved by the production profile:

- **Noisy aggregates are off in production.** They return only after `docs/design/PRIVACY_ACCOUNTING.md` is
  implemented, meets its acceptance criteria and is independently reviewed.
- **Threat-engine state** is in memory per process (blocks reset on restart, not shared between instances).
- **No native TLS for the PostgreSQL proxy** (above).
- **Secrets via environment variables**, not `*_FILE`/secret mounts.
- **The container runs as root.** The image has no dedicated user yet.
- **MySQL has no reference Compose stack.** The restricted-account path is tested (above), but you wire up the
  database and network yourself.
- **Audit log** is a local, unkeyed hash chain: ship it to an external store if a host administrator is in your
  threat model.
