# REA experiment — reproducible artifacts

Supporting material for the four reports in `docs/research/`
(`REA_EXPERIMENT.md`, `REA_BASELINE_MASKGUARD.md`, `SECURITY_COMPARISON.md`,
`REA_EVIDENCE.md`, `IMPROVEMENT_BACKLOG.md`). All data is **synthetic**.

```
fixture.sql                 synthetic customers/accounts (fake SSNs 9xx, 555-01xx phones, example.com)
anon_rules.sql              PostgreSQL Anonymizer masking rules + masked role + RLS (mirrors MaskGuard "support")
maskguard_overrides.yaml    explicit PII tags so classification is not a variable in the comparison
harness/scenarios.py        the 47 indirect-SQL scenarios + per-scenario leak predicate
harness/run.py              runs every scenario on both systems; records before/after source digests
evidence/
  scenario_matrix.json      full machine-readable result of all 47 scenarios on both systems
  ctas_bypass_repro.txt     verbatim psql transcript of the CTAS/SELECT INTO bypass (finding A)
  versions.txt              target .deb sha256, image digests, anon.so sha256, rea/node versions
  rea_doctor.txt            REA readiness report (all deep providers missing)
  rea_inspect_artifact.json REA safe artifact-graph evidence for anon.so
  rea_process_capture.json  REA PTY capture of a masked psql session (trimmed)
  anon_so_readelf.txt       ELF layout of the shipped extension
  anon_so_symbols_excerpt.txt / anon_so_strings_excerpt.txt   binary↔source tie
```

`run.py` expects a PostgreSQL Anonymizer container on `127.0.0.1:5441` (db
`rea`, masked role `support_m`) and a scratch PostgreSQL db `rea_fixture` on
`127.0.0.1:5433`, both loaded from `fixture.sql`; see `REA_EXPERIMENT.md`
"Reproducing this experiment". The paths to MaskGuard's policy files in `run.py`
are illustrative of the run that produced the evidence here.
