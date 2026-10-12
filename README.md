# MaskGuard

Query-time PII masking gateway. Admin sees real values, Support sees partial masks (`4111-XXXX-XXXX-1111`),
Analyst sees redactions or keyed-HMAC tokens. Stored data is never changed.

Every base table in a query is replaced by a masked derived table, so aliases, `SELECT *`, CTEs, subqueries,
joins, predicates, ORDER BY and aggregates only ever see masked values. Anything that isn't a single SELECT,
or uses an unregistered table or function, is rejected. The role comes from an authenticated session, never
from the SQL, and the hash-chained audit log strips literals so PII never reaches it.

```bash
uv sync
make test    # attack suite + scanner/mask tests (SQLite)
make bench   # gateway overhead vs. direct SQL on this machine
```

Known limits: HMAC tokens still allow equality joins and frequency analysis; partial masks reveal their visible
digits; a sensitive column the scanner misses is exposed; the app must not hold direct DB credentials; the
aggregation floor (minimum group size) and the PostgreSQL backend are not in this repo yet.
