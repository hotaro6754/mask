"""Streamlit dashboard. Run: maskguard dashboard   (or: streamlit run src/maskguard/dashboard.py)"""
import statistics, time

import pandas as pd
import streamlit as st

from maskguard import config
from maskguard.attacks import run_suite, score
from maskguard.rewriter import Rejected
from maskguard.scanner import scan, summary

st.set_page_config(page_title="MaskGuard", page_icon="🛡️", layout="wide")

EXAMPLES = {
    "Customers + cards (join)": "SELECT u.id, u.name, u.email, u.ssn, a.credit_card, a.balance\n"
                                "FROM users u JOIN accounts a ON a.user_id = u.id\nORDER BY u.id LIMIT 10",
    "Everything in users": "SELECT * FROM users LIMIT 10",
    "Indian IDs": "SELECT name, phone, aadhaar, pan FROM users LIMIT 10",
    "Disguised headers (tickets)": "SELECT id, contact, payment_ref, order_ref, notes FROM support_tickets LIMIT 10",
    "Aggregate by city": "SELECT city, count(*) AS customers FROM users GROUP BY city ORDER BY customers DESC",
    "Alias trick": "SELECT email AS mail, ssn AS x FROM users LIMIT 10",
}


PERF_QUERIES = ["SELECT * FROM users WHERE city = 'Pune'",
                "SELECT a.credit_card, u.email FROM accounts a JOIN users u ON u.id = a.user_id LIMIT 50",
                "SELECT status, count(*), avg(balance) FROM accounts GROUP BY status"]


@st.cache_resource
def get_app():
    return config.build(start_worker=True)


def frame(cols, rows):
    seen, names = {}, []
    for c in cols:  # Streamlit needs unique column names
        seen[c] = seen.get(c, 0) + 1
        names.append(c if seen[c] == 1 else f"{c}_{seen[c]}")
    return pd.DataFrame([[None if v is None else str(v) for v in r] for r in rows], columns=names)


app = get_app()
gw, backend = app.gateway, app.backend
if "baseline" not in st.session_state:
    st.session_state.baseline = {t: backend.checksum(t) for t in backend.tables()}

# ---- sidebar: login / role toggle -------------------------------------------------------------------------
with st.sidebar:
    st.title("🛡️ MaskGuard")
    st.caption(f"Backend: **{backend.dialect}** · tables: {', '.join(backend.tables())}")
    if config.DEMO_ENABLED and not st.session_state.get("manual"):
        role = st.radio("Role (demo accounts)", list(config.DEMO_ACCOUNTS), horizontal=True, key="role_toggle",
                        format_func=str.title)
        user, pw = config.DEMO_ACCOUNTS[role]
        st.session_state.session = app.auth.login(user, pw)
    with st.expander("Log in with a username and password"):
        u = st.text_input("Username")
        p = st.text_input("Password", type="password")
        if st.button("Log in"):
            try:
                st.session_state.session = st.session_state.manual = app.auth.login(u, p)
                st.rerun()
            except PermissionError:
                st.error("Bad credentials")
        if st.session_state.get("manual") and st.button("Log out"):
            st.session_state.manual = st.session_state.session = None
            st.rerun()
    s = st.session_state.get("session")
    if s:
        st.success(f"Signed in as **{s.user}** · role **{s.role}**")
    st.markdown("**Policy**")
    st.dataframe(pd.DataFrame(gw.policy["roles"]).T, width="stretch")

if not s:
    st.info("Log in to run queries.")
    st.stop()

t_query, t_scan, t_attack, t_integrity, t_audit, t_perf = st.tabs(
    ["Query console", "PII scanner", "Attack suite", "Data integrity", "Audit log", "Performance"])

# ---- query console --------------------------------------------------------------------------------------
with t_query:
    pick = st.selectbox("Example", list(EXAMPLES))
    sql = st.text_area("SQL", EXAMPLES[pick], height=130)
    compare = st.checkbox("Compare all roles side by side", value=True, disabled=not config.DEMO_ENABLED)
    if st.button("Run query", type="primary"):
        if compare and config.DEMO_ENABLED:
            cols = st.columns(len(config.DEMO_ACCOUNTS))
            for col, (role, (user, pw)) in zip(cols, config.DEMO_ACCOUNTS.items()):
                with col:
                    st.subheader(role.title())
                    try:
                        r = gw.query(app.auth.login(user, pw), sql)
                        st.dataframe(frame(r.columns, r.rows), width="stretch", hide_index=True)
                        st.caption(f"{len(r.rows)} rows · {r.ms:.1f} ms · masked: {', '.join(r.masked) or 'nothing'}")
                    except Rejected as e:
                        st.error(f"Rejected: {e}")
                    except Exception as e:
                        st.error(f"Query failed: {type(e).__name__}: {e}")
        else:
            try:
                r = gw.query(s, sql)
                st.dataframe(frame(r.columns, r.rows), width="stretch", hide_index=True)
                st.caption(f"{len(r.rows)} rows · {r.ms:.1f} ms · masked: {', '.join(r.masked) or 'nothing'}")
                with st.expander("Rewritten SQL that actually ran"):
                    st.code(r.rewritten_sql, language="sql")
            except Rejected as e:
                st.error(f"Rejected: {e}")
            except Exception as e:
                st.error(f"Query failed: {type(e).__name__}: {e}")

# ---- scanner --------------------------------------------------------------------------------------------
with t_scan:
    st.write("Columns tagged by a LightGBM classifier over sampled values plus checksum rules (Verhoeff, Luhn, PAN, "
             "GSTIN, IBAN, EPIC); checksum-confirmed tags always win, uncertain columns are still masked for review. "
             "A background worker rescans every "
             f"{app.settings.scan_interval}s; unscanned tables are rejected until tagged.")
    if s.role == "admin" and st.button("Rescan now"):
        gw.update_registry(scan(backend, overrides=config._load_yaml(app.settings.overrides)))
        st.success("Rescanned")
    st.dataframe(pd.DataFrame(summary(gw.registry)), width="stretch", hide_index=True)
    if app.worker:
        st.caption(f"Background worker alive: {app.worker.is_alive()} · last error: {app.worker.last_error or 'none'}")

# ---- attack suite ---------------------------------------------------------------------------------------
with t_attack:
    st.write(f"Runs every attack as **{s.role}**, once through naive output-column masking and once through "
             "MaskGuard, and checks whether real values (or inference signals) come back.")
    if st.button("Run attack suite", type="primary"):
        results = run_suite(gw, s)
        sc = score(results)
        a, b, c = st.columns(3)
        a.metric("Naive masking: PII leaks", f"{sc['naive_leaks']} / {sc['pii_attacks']}")
        b.metric("MaskGuard: PII leaks", f"{sc['maskguard_leaks']} / {sc['pii_attacks']}")
        c.metric("Unsafe statements rejected", f"{sc['firewall_rejected']} / {sc['firewall_attacks']}")
        st.dataframe(pd.DataFrame([{"attack": r["attack"], "category": r["category"], "naive": r["naive"]["status"],
                                    "MaskGuard": r["maskguard"]["status"], "naive detail": r["naive"]["detail"],
                                    "MaskGuard detail": r["maskguard"]["detail"]} for r in results]),
                     width="stretch", hide_index=True)

# ---- integrity ------------------------------------------------------------------------------------------
with t_integrity:
    st.write("SHA-256 of every row in each table, taken when the dashboard started and again now. "
             "Masking happens at query time, so these must never change.")
    now = {t: backend.checksum(t) for t in backend.tables()}
    st.dataframe(pd.DataFrame([{"table": t, "at start": st.session_state.baseline.get(t, "")[:16],
                                "now": h[:16], "unchanged": "✅" if st.session_state.baseline.get(t) == h else "❌"}
                               for t, h in now.items()]), width="stretch", hide_index=True)

# ---- audit ----------------------------------------------------------------------------------------------
with t_audit:
    ok = gw.audit.verify()
    (st.success if ok else st.error)("Hash chain intact" if ok else "Hash chain BROKEN - log was modified")
    rows = gw.audit.tail(50)[::-1]
    st.dataframe(pd.DataFrame([{k: e.get(k) for k in ("ts", "user", "role", "decision", "sql", "masked", "reason",
                                                       "rows", "ms")} for e in rows]),
                 width="stretch", hide_index=True)
    st.caption("Literals are replaced with ? before logging, so values typed into queries never reach the log.")

# ---- performance ----------------------------------------------------------------------------------------
with t_perf:
    n = st.slider("Runs", 20, 300, 100, step=20)
    q = st.selectbox("Query (presets only: the direct baseline bypasses masking)", PERF_QUERIES)
    if st.button("Measure"):
        direct, gated = [], []
        for _ in range(n):
            t0 = time.perf_counter(); backend.execute(q); direct.append((time.perf_counter() - t0) * 1000)
            t0 = time.perf_counter(); gw.query(s, q); gated.append((time.perf_counter() - t0) * 1000)
        pct = lambda xs, p: sorted(xs)[min(len(xs) - 1, int(len(xs) * p))]
        a, b, c = st.columns(3)
        a.metric("Direct p50", f"{statistics.median(direct):.2f} ms")
        b.metric("MaskGuard p50", f"{statistics.median(gated):.2f} ms")
        c.metric("MaskGuard p95", f"{pct(gated, .95):.2f} ms")
        st.caption("Includes parsing, rewriting, masking functions and the audit write.")
