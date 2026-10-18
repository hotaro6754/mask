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

A version can be published only once. To fix a released version, bump the number and release again.

## Installing unreleased changes from GitHub

To get changes made after the last release, install straight from the repository:

```bash
pip install "git+https://github.com/hotaro6754/mask@claude/zealous-bell-me62fn"
# or, as an isolated command-line tool:
uv tool install "git+https://github.com/hotaro6754/mask@claude/zealous-bell-me62fn"
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
