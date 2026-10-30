# Releasing MaskGuard to PyPI

MaskGuard is on PyPI (<https://pypi.org/project/maskguard/>). Anyone can install it with:

```bash
pip install maskguard
```

Releases are published by GitHub Actions (`.github/workflows/release.yml`) using **PyPI Trusted Publishing**: PyPI
trusts this repository's release workflow directly, so no password or API token is stored in GitHub. The workflow
runs when a version tag such as `v1.0.0` is pushed.

## One-time setup (done for 1.0.0; kept for reference)

1. **Create a PyPI account** at <https://pypi.org/account/register/> and turn on two-factor authentication. PyPI
   requires it for publishing.
2. **Register the release workflow as a "pending publisher".** This reserves the name `maskguard` for this
   repository. Go to <https://pypi.org/manage/account/publishing/> → "Add a new pending publisher" → GitHub, and
   fill in:

   | Field | Value |
   |---|---|
   | PyPI Project Name | `maskguard` |
   | Owner | `hotaro6754` |
   | Repository name | `mask` |
   | Workflow name | `release.yml` |
   | Environment name | `pypi` |

3. **Create the `pypi` environment in GitHub**: repository → Settings → Environments → New environment → `pypi`.
   Optionally add yourself as a required reviewer, so every release waits for your approval.

## Publishing a release

1. **Set the version** in `pyproject.toml` (`version = "1.0.0"`). It is the only place the version is written; the
   CLI and API read it from the installed package.
2. **Commit, then tag that commit and push the tag:**

   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

3. **Watch the run**: repository → Actions → Release. The run:
   - checks that the tag matches the version in `pyproject.toml`;
   - builds the wheel and the source package;
   - installs the wheel into a clean environment and runs it from an empty folder: `maskguard status`, a
     four-role comparison, and a check that production refuses the bundled demo users;
   - publishes to PyPI. With a required reviewer, it waits for your approval first.
4. **Check it**: `pip install maskguard` in a fresh environment, then `maskguard version`.

A version can be published only once. PyPI never lets a version's files be replaced, even after deleting them, so
to fix a released version, bump the number and release again. Optionally **yank** the old version on PyPI
(project → Manage → the version → Options → Yank): `pip install maskguard` then skips it, but anyone who pinned it
can still install it.

| Version | Date | What changed |
|---|---|---|
| 1.0.0 | 18 Oct 2026 | First release |
| 1.1.0 | 25 Oct 2026 | 128-bit analyst tokens with optional per-column scope (`mg_token`; run `db-install` after upgrading); non-null sampling, a sparse-identifier review band, and the model scoring 20-value blocks (200-value samples no longer miss addresses); policy changes between non-comparable actions need confirmation; owner-only audit file and anchorable chain head; attack matrix + fuzzer; sampling and scale benchmarks; MySQL masked views merged (fast `LIMIT` queries) |
| 1.0.3 | 18 Oct 2026 | Own-database onboarding (`maskguard connect`, first-run choice, no demo data in your database); development keys generated automatically; `HEALTH` class and automatic detection of health data, staff names, personal attributes and amounts; `pii approve [--suggested]` / `pii tag`; CLI integrity proof in production; end-to-end container test |
| 1.0.2 | 18 Oct 2026 | Rule-based scanner (the fallback without LightGBM) checks free text for identifiers; `status` warns and `doctor` explains when the ML scanner can't load (missing OpenMP runtime) |
| 1.0.1 | 18 Oct 2026 | Security fixes from an external source audit: unreviewed columns fail closed, SQL comments and MySQL hints stripped, no database error text through the proxy or dashboard, `query` capability enforced on every path |

## Installing unreleased changes from GitHub

To get changes made after the last release, install straight from the repository:

```bash
pip install "git+https://github.com/hotaro6754/mask@claude/zealous-bell-me62fn#subdirectory=FULL_CODE"
# or, as an isolated command-line tool:
uv tool install "git+https://github.com/hotaro6754/mask@claude/zealous-bell-me62fn#subdirectory=FULL_CODE"
```

## What the package contains

| Included | Not included |
|---|---|
| The `maskguard` command and Python package | Tests, benchmarks, docs and the demo video |
| The Control Room dashboard files | The Docker and Compose files (use the repository for those) |
| The trained scanner and threat models | The Postman collection (`/postman` answers 404 in a pip install) |
| The default policy, overrides and demo users (`maskguard/policies/`) | |
| `LICENSE` and `NOTICE` | |

A pip install writes its working data (`bank.db`, `audit.jsonl`, `registry.yaml`, integrity files) to `./data/` in
the folder you run it from. Set `MASKGUARD_DB`, `MASKGUARD_AUDIT` and `MASKGUARD_STATE_DIR` to put them elsewhere.

In production the bundled demo user store is refused, exactly like the repository's copy. Production always needs
`MASKGUARD_USERS` pointing at your own user file.
