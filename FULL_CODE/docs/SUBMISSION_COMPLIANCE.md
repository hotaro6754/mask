# Submission compliance: TalentAP Participant Coding Guidelines v1.1

Checked on 31 October 2026 against the guidelines' twelve rules and the submission checklist on page 4. Each line says
what was required, where MaskGuard meets it, and anything that is a judgement call.

## Before you upload (page 4)

| Requirement | Status | Evidence |
|---|---|---|
| Zip a fresh `git clone` (keeps `.git`, leaves out `.env` and ignored files) | Met | `FULL_CODE/scripts/package_submission.sh TEAMID PSID` clones, checks, then zips |
| Zip named `teamID_psID.zip`; all code in `FULL_CODE/`; our own `README.md` next to it | Met | Top level: `README.md`, `.gitignore`, `LICENSE`, `FULL_CODE/` (plus hidden `.git`, `.github`). The script refuses anything else |
| No secrets: `.env` excluded, `.env.example` included | Met | `.gitignore` lists `.env`, `deploy/production.env`, `deploy/secrets/`; `FULL_CODE/.env.example` and `deploy/production.env.example` hold dummy values |
| No `node_modules`, virtual environments, build output, large data or model files | Met, one judgement call | The script refuses `.venv`, `node_modules`, `__pycache__`, `*.db`, `*.sqlite`, `*.pkl`, zips and `data/`. The 0.7 MB classifier (`src/maskguard/ml/pii_lgbm.txt.gz`) is committed: it is our own model, in LightGBM's text format (not a pickle), the package needs it to run offline, and `bench/evaluate.py --ablation` retrains it exactly from the training scripts |
| Lockfile committed | Met | `FULL_CODE/uv.lock` |
| Formatter and linter run, warnings fixed | Met | `uv run ruff format --check` and `uv run ruff check`: clean; rules and every exception, with its reason, in `pyproject.toml` |
| Tests included, with the command to run them | Met | `FULL_CODE/tests/`; README "Tests and CI": `uv run pytest -q` |
| README covers what, how to run, architecture, AI usage, pre-built code and limitations | Met | README sections: The problem we solve, Quick start, How it works, AI usage, Pre-built and third-party code, Known limits, Where the data goes |
| Notebooks run top to bottom | Not applicable | No notebooks |

## The twelve rules

| Rule | Status | Evidence or note |
|---|---|---|
| 1. Code others can read | Mostly | Formatter and linter clean; no debug prints or commented-out code in `src/`. Open item: `cli.py` is 1,870 lines (one function per command); splitting it is the next refactor |
| 2. Clear structure | Met | All code in `FULL_CODE/`; one entry point (`maskguard`, `src/maskguard/cli.py`); settings in environment variables (`.env.example`); business logic (`gateway.py`, `rewriter.py`, `policy.py`) is separate from the web framework (`api.py`); demo schema in `src/maskguard/db/schema.sql` with `seed.py` as the seed script; no database files committed |
| 3. Secrets out of the code | Met | Secrets from environment variables only; production refuses default or missing secrets (`tests/test_production.py`); errors and logs never print tokens or values |
| 4. Secure code | Met | Input validated (Pydantic models on the API; SQL parsed and allow-listed); parameterised queries for values, quoted identifiers for names; permissions checked on the server for every route; no CORS headers sent, so browsers allow only the same origin; TLS verification on; no `eval`, `exec`, shell commands or pickle. Details: [SECURITY_ANALYSIS.md](SECURITY_ANALYSIS.md) |
| 5. Dependencies | Met | Lockfile; `pip-audit` reports no known vulnerabilities (Pillow and certifi upgraded on 31 Oct); unused `joblib` removed; licences listed in the README and `NOTICE` |
| 6. Tests that matter | Met | 1,300+ tests asserting real outputs: masks, leaks, refusals, policy decisions, model outputs, audit chain. Edge cases: empty, malformed, quoted and placeholder values; expired tokens; failed writes |
| 7. Clean repository | Met | Meaningful commit messages; `.gitignore` for Python and Node; only synthetic data (no real Aadhaar, PAN or card numbers: generated values pass check digits by construction) |
| 8. Errors handled | Met | Specific exceptions where the set is known; boundary handlers that turn any failure into a safe refusal carry their reason in place; logging, not print, for events; timeouts on HTTP calls (SDK) and database connections |
| 9. LLMs and AI APIs | Not applicable | MaskGuard calls no LLM or external AI API |
| 10. Agents, tools and MCP | Not applicable | MaskGuard runs no agent |
| 11. Data science and ML | Met | Fixed seeds; source-separated splits with a leakage check (no test column equals a training column); baselines on the same columns; metrics that fit an imbalanced multiclass task (macro-F1, per class, protection recall); no pickle; no datasets or downloaded weights committed. [AI_EVALUATION.md](AI_EVALUATION.md) |
| 12. README | Met | See the checklist above. Comments explain why; key functions have docstrings |

## Fair play and originality

- All application code was written for this hackathon, in this repository, from 12 October 2026. No code from past
  projects or other hackathons; no starter kit.
- AI coding assistants were used (Claude Code for most of the code and documents, ChatGPT for strategy notes) and are
  declared in the README.
- Third-party material (libraries, fonts, datasets) is listed with licences in the README and `NOTICE`.

## Still to do by the team before upload

- Put the team ID in the zip name: `FULL_CODE/scripts/package_submission.sh <TEAMID> B1`.
- Check the zip's size against any upload limit: the clone carries the git history (about 80 MB, mostly the demo
  videos' history).
