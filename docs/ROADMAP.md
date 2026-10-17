# MaskGuard roadmap

| Phase | Scope | Status |
|---|---|---|
| 1. ML PII discovery | LightGBM column classifier (85 features incl. checksum pass-rates) + checksum rules, 20 PII kinds incl. Indian IDs; fail-closed review band; evaluated on bharat-pii-bench | **built** |
| 2. PII inside free text | DB-side redaction of 16 identifier types inside notes/comments (SQLite UDF + generated PL/pgSQL, byte-identical); `PII_IN_TEXT` tag; T3 eval: 100% of structured IDs, 0% over-redaction | **built**; names/addresses in text need NER (ai4privacy-300k / pii-masker, blocked until `huggingface.co` is allowed) |
| 3. Query-stream threat detection | rules + IsolationForest over 5-min and 24-h windows; alert/block policy; dashboard, API, CLI | **built**: simulated eval 0% normal users blocked (2% alerted), 95–100% of 6 attack types detected, median 8 queries |
| 4. Differential-privacy aggregates | `aggregate` policy action: clipped SUM/AVG/COUNT + Laplace noise + per-user daily ε budget; any other use fails closed | **experimental, disabled in production** pending `docs/design/PRIVACY_ACCOUNTING.md`; measured: ε=0.5 → AVG error 5.4% (n=150); differencing attack median error ₹22 lakh vs ₹4.45 lakh mean balance |
| 5. Drop-in integration | PostgreSQL wire-protocol proxy (simple + extended protocol; tested with psql and psycopg), MySQL 8.4 backend (masking, HMAC, redaction byte-identical to Python), Python SDK, Postman collection (19 assertions pass under Newman), GitHub Actions CI on 3 databases | **built** |
| 6. Proof | docs/EVALUATION.md, automated PIA (`maskguard pia`, API, dashboard), updated deck and demo video | **built** |

## How this answers the research gaps in Prabowo et al., IEEE Access 2025 (doi:10.1109/ACCESS.2025.3540878)

| Gap named in the survey | MaskGuard |
|---|---|
| Table 6: data masking gives "limited protection against sophisticated attacks" | masks at the table source; inference attack suite (0/17 leaks vs 13–15/17 for naive masking) |
| §IV-D-6: hashing PII is vulnerable "due to the finite pre-image space" | keyed HMAC tokens, key held outside the database user's reach |
| Gap 1 / §IV-F-1: automated PIA using AI/ML | ML scanner + policy + audit log → generated PIA report (Phase 6) |
| Gap 5 / §IV-F-6: balance privacy and utility, preserve fidelity | joinable tokens, partial masks, DP aggregates with measured utility (Phase 4) |

## Next

- Named-entity recognition for names and addresses inside free text (ai4privacy/pii-masking-300k, HydroXai/pii-masker;
  needs `huggingface.co` network access).
- A safe, synthetic `pg_catalog` for GUI tools (DBeaver, Metabase) on the wire proxy.
- Recalibrating the threat engine on a real deployment's normal traffic.
