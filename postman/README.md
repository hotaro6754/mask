# Postman / Newman suite

| File | What it is |
|---|---|
| `Smart-Data-Masking.postman_collection.json` | 54 requests, 119 assertions, run in order |
| `Local.postman_environment.json` | `baseUrl` plus the synthetic `support.sam` demo account (never put real credentials here) |
| `build_collection.py` | Generates the collection; edit this, not the JSON |

The suite checks response **bodies**, not only status codes. It runs these stages in order:

| Folder | What it proves |
|---|---|
| 00 Service health | `/health`, `/ready` (database, scanner, policy, audit chain and integrity baseline all OK, default action `deny`), `/meta` without secrets |
| 01 Authentication | Demo identities for admin, support, analyst and auditor; password login; wrong password → 401; unknown demo role → 404 |
| 02 Integrity baseline | Records the source-table digest before anything runs |
| 03 Same query, four roles | Admin gets real values. Support gets exactly `XXX-XX-` plus the last four digits. Analyst gets 16-hex HMAC tokens and redacted names. Auditor gets `REDACTED` everywhere. Also covers cross-role compare, the query builder (no frozen accounts for Support) and DP aggregates that charge ε |
| 04 Policy inspection | Effective policy, a per-field explanation, Support explaining Admin → 403, the role matrix, and roles redacted for non-auditors |
| 05 Negative and security | No token, a tampered token, unsigned `alg:none`, a role sent in the body, stacked statements, UPDATE, catalog reads, `load_extension`, direct `mg_hmac`, CTE shadowing, `lower(ssn)`, an equality oracle, a subquery around the row filter, error-message echo, malformed JSON, query-builder injection, capability denials (403), weakening a rule without confirmation (409), an unknown action (400), and a check that the policy version did not change |
| 06 Audit trail | Hash chain valid, no SSN anywhere in the log; the Support query is found by request id with user, channel, policy version and masked columns; rejections and denials are logged |
| 07 Integrity after | Digest identical to the baseline, every table MATCH, and the full immutability proof PASS |

## Run it

Start the API on a fresh demo database, then run the collection:

```bash
# Linux / macOS
export MASKGUARD_HMAC_KEY=dev-only-hmac-key MASKGUARD_JWT_SECRET=dev-only-jwt-secret-0123456789-0123456789
uv run maskguard serve --port 8000 &
npx -y newman@6 run postman/Smart-Data-Masking.postman_collection.json -e postman/Local.postman_environment.json
```

```powershell
# Windows PowerShell
$env:MASKGUARD_HMAC_KEY="dev-only-hmac-key"; $env:MASKGUARD_JWT_SECRET="dev-only-jwt-secret-0123456789-0123456789"
Start-Process uv -ArgumentList "run","maskguard","serve","--port","8000"
npx -y newman@6 run postman/Smart-Data-Masking.postman_collection.json -e postman/Local.postman_environment.json
```

**In CI,** add `--reporters cli,junit --reporter-junit-export newman.xml`; Newman exits non-zero on any failed
assertion. See `.github/workflows/ci.yml`.

**In the Postman app,** import both files, select the *MaskGuard · Local* environment and run the collection with
the Collection Runner. The running API also serves the collection at `GET /postman`.

**Notes**
- The suite needs **demo mode**: the default when `MASKGUARD_ENV` isn't `production`. With demo mode off,
  `/auth/demo` returns 404 by design. Log in with real accounts instead.
- Run it against a **fresh** server. The threat engine watches each user's query stream, so re-running the
  negative folder many times in quick succession can eventually alert on `support.sam`. That is the detector
  working, not a test bug.
- Regenerate the JSON after editing: `python postman/build_collection.py`.
