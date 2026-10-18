# MaskGuard

**AI-powered PII discovery and query-time, role-based masking for PostgreSQL, MySQL and SQLite.**

MaskGuard is a gateway between people and the database. It finds sensitive columns by looking at their values (a
LightGBM classifier plus checksum validators for Aadhaar, PAN, GSTIN, cards, IBAN and more). It rewrites every query
so the database itself returns only what the caller's role may see. It watches for probing, and records every
decision in a hash-chained audit log. Stored data never changes.

| Role | Sees |
|---|---|
| Admin | real values |
| Support | partial masks: `4111-XXXX-XXXX-1111`, `XXX-XX-6789`, `r***@bank.in`, rounded balances |
| Analyst | keyed tokens (joinable, not reversible); no individual balances |
| Auditor | `REDACTED`, plus the audit log, policies and integrity proofs |

![One query as four roles](https://raw.githubusercontent.com/hotaro6754/mask/claude/zealous-bell-me62fn/docs/img/control-room-playground.png)

## Install and try it

```bash
pip install maskguard
export MASKGUARD_HMAC_KEY=dev-only-hmac-key-change-me     # Windows PowerShell: $env:MASKGUARD_HMAC_KEY="..."
maskguard                                                # console with synthetic demo data (created in ./data/)
maskguard compare "SELECT name, ssn, phone FROM users LIMIT 2" --roles admin,support,analyst,auditor
maskguard serve                                          # REST API + Control Room at http://127.0.0.1:8000/ui/
```

Demo logins: `admin.ann`, `support.sam`, `analyst.ali` and `auditor.aud`, each with password `<role>123`. Data,
the audit log and the scanner registry are written to `./data/` in the folder you run it from.

To use your own database, set `MASKGUARD_DB` (`postgresql://…` or `mysql://…`). For real data, run in production
mode (`MASKGUARD_ENV=production`): it refuses to start on any unsafe setting.

## Results

- **PII discovery:** 0.965 F1 with misleading column names and 5 sample values per column; the benchmark baseline
  scores 0.844.
- **Attack suite:** 0 of 17 bypass and inference attacks leak, against 14–15 of 17 for output-only masking.
- **Tests:** 476 tests on SQLite, PostgreSQL 16 and MySQL 8.4.
- **Latency:** about 8 ms added per query.

## Learn more

- [README and screenshots](https://github.com/hotaro6754/mask/blob/claude/zealous-bell-me62fn/README.md)
- [Beginner's guide](https://github.com/hotaro6754/mask/blob/claude/zealous-bell-me62fn/docs/GUIDE.md): every term,
  with diagrams and step-by-step workflows
- [Deployment guide](https://github.com/hotaro6754/mask/blob/claude/zealous-bell-me62fn/docs/DEPLOYMENT.md)
- [8-minute walkthrough video](https://github.com/hotaro6754/mask/blob/claude/zealous-bell-me62fn/docs/demo_full.mp4)

Noisy analyst aggregates are experimental and refused in production until an independent privacy review. Licensed
under Apache-2.0.
