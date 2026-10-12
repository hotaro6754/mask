# MaskGuard roadmap

| Phase | Scope | Status |
|---|---|---|
| 1. ML PII discovery | LightGBM column classifier (85 features incl. checksum pass-rates) + checksum rules, 20 PII kinds incl. Indian IDs; fail-closed review band; evaluated on bharat-pii-bench | **built** |
| 2. PII inside free text | DB-side redaction of 16 identifier types inside notes/comments (SQLite UDF + generated PL/pgSQL, byte-identical); `PII_IN_TEXT` tag; T3 eval: 100% of structured IDs, 0% over-redaction | **built**; names/addresses in text need NER (ai4privacy-300k / pii-masker, blocked until `huggingface.co` is allowed) |
| 3. Query-stream threat detection | rules + IsolationForest over session features; enumeration/differencing detection; auto-block | planned |
| 4. Differential-privacy aggregates | `aggregate` policy action: clipped SUM/AVG/COUNT + Laplace noise + per-user ε budget | planned |
| 5. Drop-in integration | PostgreSQL wire-protocol proxy, MySQL backend, Python SDK, Postman collection, CI | planned |
| 6. Proof | EVALUATION.md with charts, automated PIA report, updated deck and video | planned |

## How this answers the research gaps in Prabowo et al., IEEE Access 2025 (doi:10.1109/ACCESS.2025.3540878)

| Gap named in the survey | MaskGuard |
|---|---|
| Table 6: data masking gives "limited protection against sophisticated attacks" | masks at the table source; inference attack suite (0/17 leaks vs 13–15/17 for naive masking) |
| §IV-D-6: hashing PII is vulnerable "due to the finite pre-image space" | keyed HMAC tokens, key held outside the database user's reach |
| Gap 1 / §IV-F-1: automated PIA using AI/ML | ML scanner + policy + audit log → generated PIA report (Phase 6) |
| Gap 5 / §IV-F-6: balance privacy and utility, preserve fidelity | joinable tokens, partial masks, DP aggregates with measured utility (Phase 4) |
