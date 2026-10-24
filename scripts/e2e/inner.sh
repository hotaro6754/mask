#!/usr/bin/env bash
# Runs inside a fresh python:3.12 container (see run.sh). PKG: wheel path or "pypi"; PGPORT, SUPER_PW: the database.
set -uo pipefail
export COLUMNS=160 PIP_ROOT_USER_ACTION=ignore PIP_DISABLE_PIP_VERSION_CHECK=1
H=127.0.0.1
pass=0
ok()   { pass=$((pass + 1)); printf '  PASS  %s\n' "$1"; }
die()  { printf '  FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | head -40; exit 1; }
step() { printf '\n== %s\n' "$1"; }
check() { local name="$1"; shift; local out; out="$("$@" 2>&1)" && ok "$name" || die "$name" "$out"; }
py()   { python3 -c "$@"; }
sql()  { python3 /e2e/sql.py "$@"; }
rand() { python3 -c "import secrets; print(secrets.token_hex(${1:-16}))"; }

step "1. install MaskGuard ($PKG) in a clean container"
if [ "$PKG" = pypi ]; then pip install -q maskguard; else pip install -q "$PKG"; fi || die "pip install"
check "maskguard version: $(maskguard version)" maskguard version
py "import lightgbm" && ok "LightGBM loads (OpenMP runtime present)" || die "LightGBM"

step "2. a new database that is not the demo: owner, read-only gateway account, clinic data"
SUPER="postgresql://postgres:$SUPER_PW@$H:$PGPORT/postgres"
OWNER_PW=$(rand); GW_PW=$(rand)
sql "$SUPER" "CREATE ROLE clinic_owner LOGIN PASSWORD '$OWNER_PW'" "CREATE ROLE clinic_gateway LOGIN PASSWORD '$GW_PW'" \
    "CREATE DATABASE clinic OWNER clinic_owner" || die "create database"
sql "postgresql://postgres:$SUPER_PW@$H:$PGPORT/clinic" "REVOKE CREATE ON SCHEMA public FROM PUBLIC" \
    "ALTER SCHEMA public OWNER TO clinic_owner" || die "schema ownership"
OWNER="postgresql://clinic_owner:$OWNER_PW@$H:$PGPORT/clinic"
GATEWAY="postgresql://clinic_gateway:$GW_PW@$H:$PGPORT/clinic"
python3 /e2e/load_clinic.py "$OWNER" && ok "clinic tables loaded by the owner" || die "load data"
check "masking functions installed once, with the owner account" maskguard db-install --db "$OWNER"
sql "$OWNER" "GRANT USAGE ON SCHEMA public TO clinic_gateway" "GRANT SELECT ON ALL TABLES IN SCHEMA public TO clinic_gateway" \
    && ok "gateway account: SELECT only" || die "grants"

step "3. production configuration: our own users and secrets, no demo anything"
mkdir -p /srv/mg && cd /srv/mg
python3 - <<'EOF' || die "users file"
import secrets, yaml
from maskguard.auth import hash_password
staff = {"dr.meera": "admin", "front.desk": "support", "data.team": "analyst", "compliance": "auditor"}
pw = {u: secrets.token_urlsafe(12) for u in staff}
yaml.safe_dump({"users": {u: {"role": r, "password_hash": hash_password(pw[u])} for u, r in staff.items()}}, open("users.yaml", "w"))
open("pw.txt", "w").write("".join(f"{u} {p}\n" for u, p in pw.items()))
EOF
pw() { awk -v u="$1" '$1 == u {print $2}' /srv/mg/pw.txt; }
export MASKGUARD_ENV=production MASKGUARD_DEMO=0 MASKGUARD_SEED_IF_EMPTY=0 MASKGUARD_DB="$GATEWAY" \
       MASKGUARD_USERS=/srv/mg/users.yaml MASKGUARD_STATE_DIR=/srv/mg/state MASKGUARD_AUDIT=/srv/mg/state/audit.jsonl \
       MASKGUARD_REGISTRY=/srv/mg/state/registry.yaml MASKGUARD_OVERRIDES=/srv/mg/overrides.yaml \
       MASKGUARD_HMAC_KEY=$(rand 32) MASKGUARD_JWT_SECRET=$(rand 32)
out=$(maskguard status 2>&1); rc=$?
[ $rc -eq 0 ] && ok "production engine starts on the read-only account (status exit 0)" || die "status" "$out"
grep -q "production · demo identities OFF" <<<"$out" && ok "production mode, demo identities off" || die "mode" "$out"
grep -q "disabled in production" <<<"$out" && ok "noisy aggregates off in production" || die "D11" "$out"
[ ! -e /srv/mg/data/secrets.yaml ] && ok "no keys generated in production" || die "generated keys in production"

step "4. automatic discovery on data MaskGuard has never seen"
maskguard pii list --json >inv.json 2>/dev/null || die "pii list"
py '
import json, sys
inv = {r["table"] + "." + r["column"]: r for r in json.load(open("inv.json"))}
want = {"patients.full_name": "PII_MEDIUM", "patients.dob": "PII_MEDIUM", "patients.mobile_no": "PII_HIGH",
        "patients.contact": "PII_HIGH", "patients.aadhaar_no": "PII_HIGH", "patients.pan_card": "PII_HIGH",
        "patients.blood_group": "HEALTH", "visits.doctor": "PII_MEDIUM", "visits.diagnosis_code": "HEALTH",
        "visits.remarks": "PII_IN_TEXT", "billing.ref_code": "FINANCIAL_CONFIDENTIAL", "billing.upi_handle": "PII_HIGH",
        "billing.amount": "FINANCIAL_CONFIDENTIAL"}
got = {k: r["tag"] for k, r in inv.items() if r["tag"] not in ("UNREVIEWED", "PUBLIC")}
assert got == want, (got, want)
unrev = {k for k, r in inv.items() if r["tag"] == "UNREVIEWED"}
sugg = {k for k, r in inv.items() if r.get("suggest") == "PUBLIC"}
assert unrev - sugg == {"patients.city", "visits.visit_date"}, unrev - sugg
assert "billing.invoice_no" in sugg  # 12 digits that fail the Aadhaar checksum: not taken for an Aadhaar
' && ok "13 sensitive columns found (incl. misleading names, health, money, staff names); invoice_no decoy not flagged" \
  || die "discovery" "$(python3 -c 'import json;[print(r["table"],r["column"],r["tag"]) for r in json.load(open("inv.json"))]')"

step "5. unreviewed columns are hidden until a person decides"
q() { maskguard query "$1" -u "$2" -p "$(pw "$2")" --json 2>&1; }
J="SELECT p.patient_no, v.visit_date FROM patients p JOIN visits v ON v.patient_no = p.patient_no LIMIT 3"
py "import json,sys; d=json.loads(sys.argv[1]); assert d['rows'] == [], d['rows']" "$(q "$J" front.desk)" \
  && ok "before review: support's join on an unreviewed key matches nothing" || die "fail closed"
check "approve the scanner's suggestions (ids, keys, short lists)" maskguard pii approve --suggested
check "classify the rest: city is personal, visit date approved" maskguard pii tag patients.city --tag PII_MEDIUM --kind address
check "approve visits.visit_date" maskguard pii approve visits.visit_date
maskguard pii list --json | py "import json,sys; assert not [r for r in json.load(sys.stdin) if r['tag']=='UNREVIEWED']" \
  && ok "nothing left unreviewed" || die "review"

step "6. one query, four roles"
Q="SELECT full_name, mobile_no, aadhaar_no, diagnosis_code FROM patients p JOIN visits v ON v.patient_no = p.patient_no ORDER BY v.visit_id LIMIT 1"
A=$(q "$Q" dr.meera); S=$(q "$Q" front.desk); N=$(q "$Q" data.team); U=$(q "$Q" compliance)
py '
import json, re, sys
a, s, n, u = (json.loads(x)["rows"][0] for x in sys.argv[1:5])
assert re.fullmatch(r"\d{12}", a[2]) and re.fullmatch(r"[6-9]\d{9}", a[1]), a          # admin: real values
assert s[0] == a[0] and s[2] == "X" * 8 + a[2][-4:] and s[3] == "REDACTED", s          # support: partial, no health
assert n[0] == "REDACTED" and re.fullmatch(r"[0-9a-f]{32}", n[2]) and re.fullmatch(r"[0-9a-f]{32}", n[3]), n
assert u == ["REDACTED"] * 4, u
' "$A" "$S" "$N" "$U" && ok "admin real · support partial · analyst tokens · auditor redacted" || die "roles" "$A $S $N $U"
REAL_AADHAAR=$(py "import json,sys; print(json.loads(sys.argv[1])['rows'][0][2])" "$A")
REAL_PHONE=$(py "import json,sys; print(json.loads(sys.argv[1])['rows'][0][1])" "$A")

step "7. attempts to get around the masking"
none() { py "import json,sys; d=json.loads(sys.argv[1]); assert d['rows'] in ([], [[0]]), d" "$1"; }
none "$(q "SELECT count(*) FROM patients WHERE aadhaar_no = '$REAL_AADHAAR'" front.desk)" && ok "equality guess on a masked Aadhaar finds nothing" || die "guess"
none "$(q "SELECT patient_no FROM patients WHERE aadhaar_no LIKE '${REAL_AADHAAR:0:4}%'" front.desk)" && ok "prefix guess finds nothing" || die "prefix"
none "$(q "SELECT patient_no FROM patients WHERE mobile_no = '$REAL_PHONE'" data.team)" && ok "analyst can't look up a phone number" || die "analyst lookup"
py "import json,sys; r=json.loads(sys.argv[1])['rows']; assert r and all('[PHONE]' in x[0] or '[AADHAAR]' in x[0] for x in r), r" \
   "$(q "SELECT remarks FROM visits WHERE remarks LIKE '%called from%' OR remarks LIKE '%Aadhaar%' LIMIT 5" front.desk)" \
   && ok "identifiers inside free text are replaced for support" || die "free text"
refused() { local out; out=$(q "$1" "$2"); rc=$?; [ $rc -eq 3 ] && grep -q "$3" <<<"$out"; }
refused "DELETE FROM patients" dr.meera "only a single SELECT" && ok "writes refused, even for admin" || die "write"
refused "SELECT usename, passwd FROM pg_catalog.pg_shadow" dr.meera "schema" && ok "system catalogs refused" || die "catalog"
refused "SELECT avg(amount) FROM billing" data.team "disabled in production" && ok "noisy aggregates refused in production" || die "D11"
q "SELECT patient_no /* leak@example.com */ FROM patients LIMIT 1" front.desk >/dev/null
grep -qE "$REAL_AADHAAR|$REAL_PHONE|leak@example.com" state/audit.jsonl && die "audit log holds values" || ok "audit log: no values, no comment text"
out=$(sql "$GATEWAY" "DELETE FROM visits" 2>&1); grep -q "permission denied" <<<"$out" && [ "$(sql "$OWNER" "SELECT count(*) FROM visits")" = 500 ] \
  && ok "the database itself refuses writes from the gateway account (500 rows intact)" || die "db-level read-only" "$out"

step "8. proofs"
out=$(maskguard integrity proof -u dr.meera -p "$(pw dr.meera)" --json 2>&1)
py "import json,sys; p=json.loads(sys.argv[1]); assert p['status']=='PASS' and p['before']==p['after'], p" "$out" \
  && ok "integrity proof from the CLI in production: PASS, source unchanged" || die "proof" "$out"
maskguard integrity proof -u front.desk -p "$(pw front.desk)" >/dev/null 2>&1; [ $? -eq 3 ] && ok "proof refused without integrity.verify" || die "proof capability"
check "integrity verify: tables match the baseline" maskguard integrity verify
check "audit hash chain intact" maskguard audit verify

step "9. the API over HTTPS"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=$H -addext "subjectAltName=IP:$H" -keyout key.pem -out cert.pem 2>/dev/null
maskguard serve --host 0.0.0.0 --port 8443 >plain.log 2>&1; [ $? -ne 0 ] && grep -qi "tls" plain.log && ok "refuses to serve off-loopback without TLS" || die "TLS required" "$(cat plain.log)"
maskguard serve --host 0.0.0.0 --port 8443 --ssl-certfile cert.pem --ssl-keyfile key.pem >api.log 2>&1 & API=$!
for _ in $(seq 1 60); do curl -sf --cacert cert.pem https://$H:8443/health >/dev/null && break; sleep 1; done
TOK=$(curl -s --cacert cert.pem https://$H:8443/auth/login -H 'content-type: application/json' \
      -d "{\"username\":\"front.desk\",\"password\":\"$(pw front.desk)\"}" | py "import json,sys; print(json.load(sys.stdin)['token'])") \
  && ok "login over HTTPS (verified certificate)" || die "login" "$(cat api.log)"
curl -s --cacert cert.pem https://$H:8443/query -H "Authorization: Bearer $TOK" -H 'content-type: application/json' \
     -d '{"sql":"SELECT aadhaar_no FROM patients LIMIT 1"}' | py "import json,sys; v=json.load(sys.stdin)['rows'][0][0]; assert v.startswith('XXXX'), v" \
  && ok "API masks for support" || die "API query"
[ "$(curl -s -o /dev/null -w '%{http_code}' --cacert cert.pem https://$H:8443/auth/demo -H 'content-type: application/json' -d '{"role":"admin"}')" = 404 ] \
  && ok "no demo login in production" || die "demo login"
[ "$(curl -s -o /dev/null -w '%{http_code}' --cacert cert.pem https://$H:8443/attacks -H "Authorization: Bearer $TOK")" = 403 ] \
  && ok "attack self-test refused in production" || die "attacks"
kill $API; wait $API 2>/dev/null

step "10. restarts and unsafe settings"
T1=$(q "SELECT aadhaar_no FROM patients ORDER BY patient_no LIMIT 1" data.team)
T2=$(q "SELECT aadhaar_no FROM patients ORDER BY patient_no LIMIT 1" data.team)
py "import json,sys; a,b=(json.loads(x)['rows'] for x in sys.argv[1:3]); assert a==b, (a,b)" "$T1" "$T2" && ok "tokens stable across processes" || die "tokens"
refuse() { local out; out=$(env "$@" maskguard status 2>&1); [ $? -eq 4 ]; }
refuse MASKGUARD_HMAC_KEY= && ok "refused: no HMAC key" || die "missing key"
refuse MASKGUARD_HMAC_KEY=dev-only-hmac-key-change-me-0123456789abcdef && ok "refused: placeholder key" || die "placeholder"
refuse MASKGUARD_DB="$SUPER" && ok "refused: superuser database account" || die "superuser"
refuse MASKGUARD_DB="$OWNER" && ok "refused: table owner account" || die "owner"
refuse MASKGUARD_USERS="$(python3 -c 'import maskguard,os;print(os.path.join(os.path.dirname(maskguard.__file__),"policies","users.demo.yaml"))')" \
  && ok "refused: demo user store" || die "demo users"
refuse MASKGUARD_DEMO=1 && ok "refused: demo mode" || die "demo mode"

step "11. development on your own database (first-time user)"
mkdir -p /srv/dev && cd /srv/dev
env -u MASKGUARD_ENV -u MASKGUARD_DEMO -u MASKGUARD_SEED_IF_EMPTY -u MASKGUARD_DB -u MASKGUARD_USERS -u MASKGUARD_STATE_DIR \
    -u MASKGUARD_AUDIT -u MASKGUARD_REGISTRY -u MASKGUARD_OVERRIDES -u MASKGUARD_HMAC_KEY -u MASKGUARD_JWT_SECRET \
    bash -c "maskguard connect '$OWNER' && maskguard status" >dev.log 2>&1 && ok "maskguard connect + status, no key set by hand" || die "connect" "$(cat dev.log)"
grep -q "generated for this machine" dev.log && [ "$(stat -c %a data/secrets.yaml)" = 600 ] && ok "key generated, saved readable only by you" || die "dev key"
[ "$(stat -c %a maskguard.yaml)" = 600 ] && ok "saved connection readable only by you" || die "settings mode"
n=$(sql "$OWNER" "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'")
[ "$n" = 3 ] && ok "no demo data written into your database" || die "demo data written ($n tables)"

printf '\nALL %d CHECKS PASSED\n' "$pass"
