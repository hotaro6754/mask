/* MaskGuard Control Room. Plain JS, no dependencies, no inline scripts (strict CSP).
   Every number and row on screen comes from the API; every role switch is a real login and a real request.
   Values from the server are always inserted as text (never as HTML). */
"use strict";

// ------------------------------------------------------------------ utilities

const $ = (sel, el = document) => el.querySelector(sel);

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "style") Object.assign(el.style, v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

const svgNS = "http://www.w3.org/2000/svg";
function s(tag, attrs, ...kids) {
  const el = document.createElementNS(svgNS, tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v);
  }
  kids.flat().forEach((k) => k && el.append(k instanceof Node ? k : document.createTextNode(String(k))));
  return el;
}

const pad = (n) => String(n).padStart(2, "0");
const fmtTime = (ts) => { const d = new Date(ts * 1000); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; };
const short = (x, n = 12) => (x ? String(x).slice(0, n) + "…" : "—");
const store = {
  get(k, d) { try { const v = sessionStorage.getItem(k); return v === null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { sessionStorage.setItem(k, JSON.stringify(v)); } catch { /* storage unavailable */ } },
  del(k) { try { sessionStorage.removeItem(k); } catch { /* ignore */ } },
};
const prefs = {
  get(k, d) { try { const v = localStorage.getItem("mg." + k); return v === null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem("mg." + k, JSON.stringify(v)); } catch { /* ignore */ } },
};

function toast(msg, kind = "info") {
  const t = h("div", { class: `toast ${kind}` }, msg);
  $("#toasts").append(t);
  setTimeout(() => t.remove(), 4200);
}

function badge(text, cls) { return h("span", { class: `badge ${cls}` }, text); }
const actionBadge = (a) => badge(a, `a-${a}`);
const tagBadge = (t) => badge(t || "UNREVIEWED", `t-${t || "UNREVIEWED"}`);
const okBadge = (ok, yes = "PASS", no = "FAIL") => badge(ok ? yes : no, ok ? "b-ok" : "b-bad");

function card(title, body, ...tools) {
  return h("section", { class: "card" },
    title ? h("header", {}, h("h2", {}, title), h("span", { class: "spacer" }), ...tools) : null,
    body);
}
const loading = (msg = "Loading…") => h("div", { class: "loading" }, msg);
const empty = (msg) => h("div", { class: "empty" }, msg);
const errorBox = (msg) => h("div", { class: "error-box", role: "alert" }, msg);
const needCap = (cap) => empty(`Your role does not have the "${cap}" capability. Switch to an Admin or Auditor identity to see this.`);

function copyBtn(text, label = "Copy") {
  return h("button", { class: "small", type: "button", onclick: async (e) => {
    try { await navigator.clipboard.writeText(text); toast("Copied to clipboard", "ok"); }
    catch { toast("Copy failed: select the text and copy manually", "warn"); }
    e.currentTarget.blur();
  } }, label);
}

// ------------------------------------------------------------------ API client

const S = { meta: null, me: null, token: null, ready: null, demoTokens: {}, tablesCache: null };

async function api(method, path, body, token) {
  const tok = token === undefined ? S.token : token;
  const headers = { "Content-Type": "application/json" };
  if (tok) headers.Authorization = `Bearer ${tok}`;
  const t0 = performance.now();
  let res;
  try {
    res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  } catch (e) {
    return { ok: false, status: 0, data: { detail: "API unreachable" }, ms: performance.now() - t0 };
  }
  const txt = await res.text();
  let data = txt;
  try { data = txt ? JSON.parse(txt) : null; } catch { /* plain text */ }
  if (res.status === 401 && tok && tok === S.token && path !== "/auth/login") { signOut(true); }
  return { ok: res.ok, status: res.status, data, ms: performance.now() - t0, rid: res.headers.get("x-request-id") };
}
const detail = (r) => (r.data && r.data.detail) ? (typeof r.data.detail === "string" ? r.data.detail : JSON.stringify(r.data.detail)) : `HTTP ${r.status}`;
const can = (cap) => !!(S.me && S.me.capabilities && S.me.capabilities.includes(cap));

async function demoToken(role) {
  if (S.demoTokens[role]) return S.demoTokens[role];
  const r = await api("POST", "/auth/demo", { role }, null);
  if (!r.ok) throw new Error(detail(r));
  S.demoTokens[role] = r.data.token;
  return r.data.token;
}

async function useToken(token) {
  const r = await api("GET", "/me", undefined, token);
  if (!r.ok) return false;
  S.token = token; S.me = r.data; store.set("mg.token", token);
  S.tablesCache = null;
  renderIdentity();
  return true;
}

async function signInDemo(role) {
  try { await useToken(await demoToken(role)); toast(`Signed in as ${S.me.user} (${S.me.role})`, "ok"); route(); }
  catch (e) { toast(`Demo sign-in failed: ${e.message}`, "bad"); }
}

function signOut(expired) {
  S.token = null; S.me = null; S.demoTokens = {}; store.del("mg.token");
  renderIdentity();
  if (expired) toast("Session expired or revoked: sign in again", "warn");
  route();
}

async function tables() {
  if (!S.tablesCache) {
    const r = await api("GET", "/tables");
    if (!r.ok) throw new Error(detail(r));
    S.tablesCache = r.data.tables;
  }
  return S.tablesCache;
}

// ------------------------------------------------------------------ identity bar + sign-in

function renderIdentity() {
  const box = $("#identity");
  box.replaceChildren();
  const ready = S.ready;
  box.append(h("span", { class: "who", title: "Readiness from /ready" },
    h("span", { class: `status-dot ${ready && ready.ready ? "ok" : "bad"}` }),
    h("span", { class: "muted small" }, ready ? (ready.ready ? "engine ready" : "engine degraded") : "checking…")));
  if (S.meta) box.append(badge(`${S.meta.backend} · policy ${S.meta.policy_version}`, "b-muted"));
  if (S.me) {
    box.append(h("span", { class: "who" }, h("span", { class: "muted" }, "signed in as"), h("span", { class: "name" }, S.me.user), badge(S.me.role, "b-info")));
  }
  if (S.meta && S.meta.demo_mode) {
    const sel = h("select", { "aria-label": "Switch demo identity", onchange: (e) => e.target.value && signInDemo(e.target.value) },
      h("option", { value: "" }, "Switch identity…"),
      S.meta.demo_identities.map((d) => h("option", { value: d.role }, `${d.role} · ${d.user}`)));
    box.append(sel);
  }
  box.append(S.me ? h("button", { class: "ghost small", onclick: () => signOut(false) }, "Sign out")
                  : h("button", { class: "small", onclick: openSignIn }, "Sign in"));
  const foot = $("#side-foot");
  foot.replaceChildren(
    h("div", {}, "env ", h("b", {}, S.meta ? S.meta.environment : "…")),
    h("div", {}, "demo identities ", h("b", {}, S.meta ? (S.meta.demo_mode ? "on" : "off") : "…")),
    h("div", {}, "data ", h("b", {}, "synthetic")),
    h("div", {}, h("a", { href: "/docs", target: "_blank", rel: "noopener" }, "OpenAPI docs ↗")));
}

function openDialog(title, body, actions) {
  const d = $("#dialog");
  d.replaceChildren(h("div", { class: "d-head" }, title), h("div", { class: "d-body" }, body),
    h("div", { class: "d-foot" }, ...actions));
  if (!d.open) d.showModal();
  return d;
}
const closeDialog = () => $("#dialog").open && $("#dialog").close();

function openSignIn() {
  const user = h("input", { autocomplete: "username", required: true });
  const pw = h("input", { type: "password", autocomplete: "current-password", required: true });
  const msg = h("div", { class: "small muted" }, "Credentials are checked by the server (PBKDF2). The role comes from the user store, never from this form.");
  const submit = async () => {
    const r = await api("POST", "/auth/login", { username: user.value, password: pw.value }, null);
    if (!r.ok) { msg.textContent = "Sign-in failed: " + detail(r); msg.className = "small error-box"; return; }
    await useToken(r.data.token); closeDialog(); toast(`Signed in as ${S.me.user}`, "ok"); route();
  };
  pw.addEventListener("keydown", (e) => e.key === "Enter" && submit());
  const demoRow = S.meta && S.meta.demo_mode
    ? h("div", { class: "stack" }, h("div", { class: "small muted" }, "Demo mode: synthetic identities, one click each."),
        h("div", { class: "chips" }, S.meta.demo_identities.map((d) => h("button", { class: "chip", onclick: () => { closeDialog(); signInDemo(d.role); } }, d.role))))
    : null;
  openDialog("Sign in", [demoRow, h("label", {}, "Username", user), h("label", {}, "Password", pw), msg],
    [h("button", { onclick: closeDialog }, "Cancel"), h("button", { class: "primary", onclick: submit }, "Sign in")]);
  user.focus();
}

// ------------------------------------------------------------------ charts (hand-rolled SVG, real data only)

function tipShow(e, lines) {
  const t = $("#tooltip");
  t.replaceChildren(...lines.map((l) => h("div", {}, l)));
  t.hidden = false;
  const x = Math.min(e.clientX + 14, window.innerWidth - t.offsetWidth - 8);
  const y = Math.min(e.clientY + 14, window.innerHeight - t.offsetHeight - 8);
  t.style.left = x + "px"; t.style.top = y + "px";
}
const tipHide = () => { $("#tooltip").hidden = true; };

function activityChart(stats) {
  const series = stats.series;
  const W = 720, H = 190, P = { l: 34, r: 8, t: 10, b: 24 };
  const vals = series.map((b) => ({ ok: b.allow || 0, bad: (b.reject || 0) + (b.denied || 0) + (b.blocked || 0) + (b.error || 0), t: b.hour_start }));
  const max = Math.max(4, ...vals.map((v) => v.ok + v.bad));
  const bw = (W - P.l - P.r) / vals.length;
  const y = (v) => H - P.b - (v / max) * (H - P.t - P.b);
  const svg = s("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": `Queries per hour, last ${stats.hours} hours: allowed and refused` });
  [0, 0.5, 1].forEach((f) => {
    const v = Math.round(max * f);
    svg.append(s("line", { class: "grid-line", x1: P.l, x2: W - P.r, y1: y(v), y2: y(v) }), s("text", { class: "axis", x: P.l - 6, y: y(v) + 3, "text-anchor": "end" }, v));
  });
  vals.forEach((v, i) => {
    const x = P.l + i * bw + 1, w = Math.max(2, bw - 2);
    const g = s("g", {});
    if (v.ok) g.append(s("rect", { x, width: w, y: y(v.ok), height: H - P.b - y(v.ok), rx: 2, fill: "#b8f15a" }));
    if (v.bad) g.append(s("rect", { x, width: w, y: y(v.ok + v.bad), height: Math.max(0, y(v.ok) - y(v.ok + v.bad) - 2), rx: 2, fill: "#ff6b6b" }));
    const hit = s("rect", { x: P.l + i * bw, width: bw, y: P.t, height: H - P.t - P.b, fill: "transparent", tabindex: 0,
      "aria-label": `${new Date(v.t * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}: ${v.ok} allowed, ${v.bad} refused` });
    const show = (e) => tipShow(e, [new Date(v.t * 1000).toLocaleString([], { hour12: false, hour: "2-digit", minute: "2-digit", month: "short", day: "numeric" }) + " +1h", `allowed  ${v.ok}`, `refused  ${v.bad}`]);
    hit.addEventListener("mousemove", show); hit.addEventListener("mouseleave", tipHide);
    hit.addEventListener("focus", (e) => { const r = e.target.getBoundingClientRect(); show({ clientX: r.left, clientY: r.top }); });
    hit.addEventListener("blur", tipHide);
    g.append(hit); svg.append(g);
  });
  [[0, `-${stats.hours}h`], [Math.floor(vals.length / 2), `-${Math.round(stats.hours / 2)}h`], [vals.length - 1, "now"]].forEach(([i, l]) =>
    svg.append(s("text", { class: "axis", x: P.l + i * bw + bw / 2, y: H - 6, "text-anchor": i === 0 ? "start" : i === vals.length - 1 ? "end" : "middle" }, l)));
  const tbl = h("details", {}, h("summary", {}, "Show as table"),
    h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Hour"), h("th", {}, "Allowed"), h("th", {}, "Refused"))),
      h("tbody", {}, vals.filter((v) => v.ok || v.bad).map((v) => h("tr", {}, h("td", {}, fmtTime(v.t)), h("td", {}, v.ok), h("td", {}, v.bad)))))));
  return h("div", { class: "chart stack" },
    h("div", { class: "legend" }, h("span", {}, h("i", { style: { background: "#b8f15a" } }), "Allowed (masked per role)"),
      h("span", {}, h("i", { style: { background: "#ff6b6b" } }), "Refused (firewall, capability, threat block)")),
    svg, tbl);
}

function hbars(rows, colorFor) {
  const max = Math.max(1, ...rows.map((r) => r[1]));
  return h("div", {}, rows.map(([label, n]) => h("div", { class: "hbar" },
    h("span", {}, tagBadge(label)), h("div", { class: "track" }, h("div", { class: "fill", style: { width: `${(n / max) * 100}%`, background: colorFor(label) } })),
    h("span", { class: "mono" }, n))));
}
const TAG_COLOR = { PII_HIGH: "#ff8f8f", FINANCIAL_CONFIDENTIAL: "#e9c46a", PII_MEDIUM: "#f2b84b", PII_IN_TEXT: "#b59cff", UNREVIEWED: "#d9a05b", PUBLIC: "#6b7684" };

// ------------------------------------------------------------------ result + explain tables

function columnActions(result) {
  const acts = {};
  (result.masked || []).forEach((m) => {
    const [target, action] = m.split(":");
    if (target.includes(".")) { const c = target.split(".")[1].toLowerCase(); if (!(c in acts)) acts[c] = action; }
  });
  return acts;
}

function resultTable(r, maxRows = 50) {
  const acts = columnActions(r);
  return h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, r.columns.map((c) => h("th", { scope: "col" }, c, acts[c.toLowerCase()] ? actionBadge(acts[c.toLowerCase()]) : null)))),
    h("tbody", {}, r.rows.slice(0, maxRows).map((row) => h("tr", {}, row.map((v, i) => {
      const a = acts[r.columns[i].toLowerCase()];
      return h("td", { class: `mono ${a ? "masked m-" + a : ""}` }, v === null ? h("span", { class: "null" }, "NULL") : String(v));
    }))))));
}

function explainTable(ex) {
  return h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, ["Field", "Classification", "Confidence", "Policy action", "Synthetic example → result", "Decided by"].map((x) => h("th", { scope: "col" }, x)))),
    h("tbody", {}, ex.columns.map((c) => h("tr", {},
      h("td", { class: "mono" }, c.column), h("td", {}, tagBadge(c.tag)), h("td", {}, c.confidence || "—"),
      h("td", {}, actionBadge(c.action), h("div", { class: "small muted" }, c.transformation)),
      h("td", { class: "mono" }, c.action === "allow" ? h("span", { class: "muted" }, "unchanged")
        : [String(c.example_in), h("span", { class: "muted" }, "  →  "), c.example_out === null ? h("span", { class: "null" }, "NULL") : String(c.example_out)]),
      h("td", { class: "mono small muted" }, c.rule))))));
}

// ------------------------------------------------------------------ pages

const PAGES = {};
const TITLES = { overview: "Overview", playground: "Masking playground", discovery: "PII discovery", policy: "Policy studio", roles: "Role explorer",
                 audit: "Audit explorer", integrity: "Data integrity", api: "API lab", cli: "CLI guide", settings: "Diagnostics" };

PAGES.overview = async (main) => {
  main.append(h("h1", {}, "Overview"),
    h("p", { class: "lede" }, "Live state of the masking gateway. Every figure below is read from the running service: the readiness checks, the scanner registry, the enforced policy and the hash-chained audit log."));
  const [ready, tbl, roles, integ, stats, audit] = await Promise.all([
    api("GET", "/ready", undefined, null), api("GET", "/tables"), api("GET", "/roles"),
    can("integrity.verify") ? api("GET", "/integrity/status") : null,
    can("audit.read") ? api("GET", "/audit/stats?hours=24") : null,
    can("audit.read") ? api("GET", "/audit?n=400") : null]);
  S.ready = ready.data; renderIdentity();
  const cols = tbl.ok ? tbl.data.tables.flatMap((t) => t.columns) : [];
  const sensitive = cols.filter((c) => c.tag !== "PUBLIC" && c.tag !== "UNREVIEWED");
  const tiles = h("div", { class: "grid cols-4" },
    card(null, h("div", { class: "stat" }, h("div", { class: "label" }, "Tables protected"), h("div", { class: "value" }, tbl.ok ? tbl.data.tables.length : "—"), h("div", { class: "hint" }, tbl.ok ? `${tbl.data.backend} · synthetic demo data` : ""))),
    card(null, h("div", { class: "stat" }, h("div", { class: "label" }, "Sensitive columns"), h("div", { class: "value" }, tbl.ok ? sensitive.length : "—"), h("div", { class: "hint" }, `of ${cols.length} columns, found by the scanner`))),
    card(null, h("div", { class: "stat" }, h("div", { class: "label" }, "Roles"), h("div", { class: "value" }, roles.ok ? roles.data.roles.length : "—"), h("div", { class: "hint" }, "default action: deny"))),
    card(null, h("div", { class: "stat" }, h("div", { class: "label" }, "Policy version"), h("div", { class: "value", style: { fontSize: "18px", marginTop: "12px" } }, S.meta.policy_version), h("div", { class: "hint" }, "written into every audit entry"))));
  const checks = ready.data && ready.data.checks ? Object.entries(ready.data.checks) : [];
  const health = card("Service health", h("div", { class: "body" }, h("div", { class: "checks" }, checks.map(([k, v]) => h("div", { class: "check" },
    h("span", {}, k.replace(/_/g, " ")), okBadge(v.ok), h("span", { class: "detail" }, Object.entries(v).filter(([x]) => x !== "ok").map(([x, y]) => `${x}=${y}`).join("  ")))))),
    okBadge(ready.data && ready.data.ready, "READY", "DEGRADED"));
  let integCard;
  if (!integ) integCard = card("Source integrity", needCap("integrity.verify"));
  else if (!integ.ok) integCard = card("Source integrity", errorBox(detail(integ)));
  else {
    const lv = integ.data.last_verification;
    integCard = card("Source integrity", h("div", { class: "body stack" },
      h("dl", { class: "kv" }, h("dt", {}, "Baseline"), h("dd", {}, integ.data.baseline ? integ.data.baseline.taken_at : "none"),
        h("dt", {}, "Digest"), h("dd", {}, integ.data.baseline ? short(integ.data.baseline.combined_sha256, 24) : "—"),
        h("dt", {}, "Last check"), h("dd", {}, lv ? `${lv.verified_at} · ${lv.actor}` : "never in this deployment")),
      lv ? h("div", { class: "row" }, badge(lv.status, lv.status === "MATCH" ? "b-ok" : "b-bad"), h("span", { class: "small muted" }, lv.status === "MATCH" ? "source records unchanged since the baseline" : "source changed since the baseline: investigate (may be a legitimate write)"))
         : h("div", { class: "small muted" }, "No verification yet: run one on the Data integrity page."),
      h("a", { href: "#/integrity", class: "btn small" }, "Open integrity checks")));
  }
  let activity, events, split;
  if (!stats) { activity = card("Masked-query activity · last 24 h", needCap("audit.read")); events = card("Recent security events", needCap("audit.read")); split = card("Decisions · 24 h", needCap("audit.read")); }
  else {
    activity = card("Masked-query activity · last 24 h", h("div", { class: "body" }, activityChart(stats.data)));
    const T = stats.data.totals || {};
    const refused = (T.reject || 0) + (T.denied || 0) + (T.blocked || 0) + (T.error || 0);
    split = card("Decisions · 24 h", h("div", { class: "body stack" },
      h("div", { class: "grid cols-2" }, h("div", { class: "stat" }, h("div", { class: "label" }, "Allowed"), h("div", { class: "value", style: { color: "var(--accent)" } }, T.allow || 0)),
        h("div", { class: "stat" }, h("div", { class: "label" }, "Refused"), h("div", { class: "value", style: { color: "var(--bad)" } }, refused))),
      h("dl", { class: "kv" }, h("dt", {}, "Firewall rejects"), h("dd", {}, T.reject || 0), h("dt", {}, "Capability denials"), h("dd", {}, T.denied || 0),
        h("dt", {}, "Threat blocks"), h("dd", {}, T.blocked || 0), h("dt", {}, "Threat alerts"), h("dd", {}, stats.data.threat_alerts),
        h("dt", {}, "Median latency"), h("dd", {}, stats.data.p50_ms === null ? "—" : `${stats.data.p50_ms} ms`))));
    const bad = (audit.data.entries || []).filter((e) => ["reject", "denied", "blocked", "error", "policy_change", "integrity_baseline", "unblock"].includes(e.decision)).reverse().slice(0, 8);
    events = card("Recent security events", bad.length ? h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, ["Time", "User", "Decision", "Detail"].map((x) => h("th", {}, x)))),
      h("tbody", {}, bad.map((e) => h("tr", {}, h("td", { class: "mono" }, new Date(e.ts * 1000).toLocaleTimeString([], { hour12: false })), h("td", { class: "mono" }, e.user),
        h("td", {}, decisionBadge(e.decision)), h("td", { class: "small" }, (e.reason || e.target || e.change || "").slice(0, 90)))))))
      : empty("No refusals, denials or policy changes recorded yet."), h("a", { href: "#/audit", class: "btn small" }, "Audit explorer"));
  }
  const cta = card(null, h("div", { class: "body row" },
    h("div", { class: "stack", style: { flex: "1" } }, h("h2", {}, "See it work: one query, every role"),
      h("div", { class: "muted" }, "Run the same SELECT as Admin, Support, Analyst and Auditor. Each run is a real request under that identity's own token; then verify the source tables did not change.")),
    h("a", { href: "#/playground", class: "btn primary" }, "Open the playground →")));
  main.append(tiles, h("div", { style: { height: "16px" } }), cta, h("div", { style: { height: "16px" } }),
    h("div", { class: "grid cols-3" }, h("div", { style: { gridColumn: "span 2" } }, activity), split),
    h("div", { style: { height: "16px" } }), h("div", { class: "grid cols-3" }, health, integCard, events));
};

function decisionBadge(d) {
  const cls = d === "allow" ? "b-ok" : ["reject", "denied", "blocked", "error", "policy_denied"].includes(d) ? "b-bad" : "b-info";
  return badge(d, cls);
}

// ---------- playground (centerpiece)

const PRESETS = [
  ["Customers: identity fields", "SELECT id, name, email, phone, ssn, aadhaar FROM users ORDER BY id LIMIT 5"],
  ["Cards and balances (joined)", "SELECT u.name, a.credit_card, a.balance, a.status FROM accounts a JOIN users u ON u.id = a.user_id ORDER BY a.id LIMIT 5"],
  ["Support notes (free text)", "SELECT id, contact, message FROM support_tickets ORDER BY id LIMIT 5"],
  ["Analyst aggregate (noisy AVG)", "SELECT status, count(*) AS n, avg(balance) AS avg_balance FROM accounts GROUP BY status"],
  ["Bypass attempt: CTE shadowing", "WITH users AS (SELECT * FROM users) SELECT name, ssn FROM users ORDER BY id LIMIT 3"],
  ["Inference attempt: equality oracle", "SELECT count(*) AS n FROM users WHERE ssn LIKE '1%'"],
  ["Write attempt (refused)", "UPDATE users SET email = 'x@example.com'"],
];

PAGES.playground = async (main) => {
  const st = store.get("mg.pg", { table: "users", mode: "builder", roles: ["admin", "support", "analyst"], sql: PRESETS[0][1], limit: 5, cols: null, verify: true });
  const save = () => store.set("mg.pg", st);
  main.append(h("h1", {}, "Masking playground"),
    h("p", { class: "lede" }, "Pick a table, pick roles, run. The same logical query is sent once per role under that role's own signed token; masking happens in the database query the gateway generates, before any value leaves the trust boundary. Data is synthetic."));
  let tbls;
  try { tbls = await tables(); } catch (e) { main.append(errorBox(e.message)); return; }
  const demo = S.meta.demo_mode;
  const allRoles = demo ? S.meta.demo_identities.map((d) => d.role) : [S.me.role];
  st.roles = st.roles.filter((r) => allRoles.includes(r));
  if (!st.roles.length) st.roles = [allRoles[0]];
  if (!tbls.find((t) => t.table === st.table)) st.table = tbls[0].table;

  const tableSel = h("select", { id: "pg-table", onchange: (e) => { st.table = e.target.value; st.cols = null; save(); renderCols(); } },
    tbls.map((t) => h("option", { value: t.table, selected: t.table === st.table }, `${t.table} (${t.columns.length} columns)`)));
  const colsBox = h("div", { class: "stack", style: { maxHeight: "260px", overflow: "auto" } });
  const limit = h("input", { type: "number", min: 1, max: 50, value: st.limit, style: { width: "80px" }, onchange: (e) => { st.limit = Math.max(1, Math.min(50, +e.target.value || 5)); save(); } });
  function renderCols() {
    const t = tbls.find((x) => x.table === st.table);
    colsBox.replaceChildren(...t.columns.map((c) => h("label", { class: "inline" },
      h("input", { type: "checkbox", checked: !st.cols || st.cols.includes(c.column), onchange: (e) => {
        const cur = new Set(st.cols || t.columns.map((x) => x.column));
        e.target.checked ? cur.add(c.column) : cur.delete(c.column);
        st.cols = t.columns.map((x) => x.column).filter((x) => cur.has(x)); save();
      } }), h("span", { class: "mono" }, c.column), tagBadge(c.tag))));
  }
  renderCols();
  const sqlBox = h("textarea", { id: "pg-sql", spellcheck: "false", "aria-label": "SQL", oninput: (e) => { st.sql = e.target.value; save(); } }, st.sql);
  const presetSel = h("select", { "aria-label": "Preset queries", onchange: (e) => { if (e.target.value) { st.sql = e.target.value; sqlBox.value = st.sql; save(); } } },
    h("option", { value: "" }, "Preset queries…"), PRESETS.map(([n, q]) => h("option", { value: q }, n)));
  const builder = h("div", { class: "stack" }, h("label", {}, "Columns", colsBox), h("label", {}, "Rows", limit));
  const sqlPane = h("div", { class: "stack" }, presetSel, sqlBox, h("div", { class: "small muted" }, "One SELECT. Writes, stacked statements, catalogs and unknown functions are refused by the server."));
  const tabs = h("div", { class: "tabs", role: "tablist" });
  const pane = h("div", { style: { paddingTop: "12px" } });
  const setMode = (m) => {
    st.mode = m; save();
    tabs.replaceChildren(...[["builder", "Query builder"], ["sql", "SQL editor"]].map(([k, l]) =>
      h("button", { role: "tab", "aria-selected": String(m === k), onclick: () => setMode(k) }, l)));
    pane.replaceChildren(m === "builder" ? builder : sqlPane);
  };
  setMode(st.mode);
  const chips = h("div", { class: "chips", role: "group", "aria-label": "Roles to compare" });
  const renderChips = () => chips.replaceChildren(...allRoles.map((r) => h("button", { class: "chip", "aria-pressed": String(st.roles.includes(r)),
    onclick: () => { st.roles = st.roles.includes(r) ? st.roles.filter((x) => x !== r) : allRoles.filter((x) => x === r || st.roles.includes(x)); if (!st.roles.length) st.roles = [r]; save(); renderChips(); } },
    h("span", { class: "dot" }), r)));
  renderChips();
  const verify = h("input", { type: "checkbox", checked: st.verify, onchange: (e) => { st.verify = e.target.checked; save(); } });
  const runBtn = h("button", { class: "primary", id: "pg-run", onclick: () => run() }, "▶ Run");
  const controls = card("Query", h("div", { class: "body stack" },
    h("label", {}, "Dataset", h("div", { class: "mono small" }, `demo_bank · ${S.meta.backend} · synthetic`)),
    h("label", {}, "Table", tableSel), tabs, pane,
    h("fieldset", {}, h("legend", {}, demo ? "Run as (demo identities)" : "Run as"), chips,
      !demo ? h("div", { class: "small muted" }, "Demo identities are off: queries run as your own identity only.") : null),
    h("label", { class: "inline" }, verify, "Verify source tables after the run"),
    h("div", { class: "row" }, runBtn, h("span", { class: "small muted" }, "Ctrl/⌘ + Enter"))));
  const out = h("div", { class: "stack", id: "pg-out" },
    card(null, empty("Choose a table and roles, then Run. Results appear side by side with the reason for every masked field.")));
  main.append(h("div", { class: "pg" }, h("div", { class: "pg-controls" }, controls), out));
  main.addEventListener("keydown", (e) => { if ((e.ctrlKey || e.metaKey) && e.key === "Enter") { e.preventDefault(); run(); } });

  async function tokenFor(role) { return demo ? demoToken(role) : S.token; }

  async function run() {
    runBtn.disabled = true;
    out.replaceChildren(card(null, loading(`Running as ${st.roles.join(", ")}…`)));
    const roles = [...st.roles];
    const body = st.mode === "builder" ? { table: st.table, columns: st.cols, limit: st.limit } : { sql: st.sql };
    const path = st.mode === "builder" ? "/query/table" : "/query";
    let results;
    try {
      results = await Promise.all(roles.map(async (r) => ({ role: r, res: await api("POST", path, body, await tokenFor(r)) })));
    } catch (e) { out.replaceChildren(errorBox(e.message)); runBtn.disabled = false; return; }
    const sql = st.mode === "builder" ? (results.find((x) => x.res.ok) || {}).res?.data?.sql : st.sql;
    const nCols = Math.max(0, ...results.map(({ res }) => (res.ok ? res.data.columns.length : 0)));
    const grid = h("div", { class: `results ${nCols > 5 ? "wide" : ""}` }, results.map(({ role, res }) => {
      if (!res.ok) {
        return card(null, h("div", {}, h("header", { class: "result-head", style: { padding: "12px 14px", borderBottom: "1px solid var(--border)" } },
            h("span", { class: "role-name" }, role), badge(res.status === 400 ? "REFUSED" : `HTTP ${res.status}`, "b-bad")),
          h("div", { class: "body stack" }, h("div", {}, detail(res)), res.rid ? h("div", { class: "mono small muted" }, `request ${res.rid} (see Audit explorer)`) : null)));
      }
      const d = res.data;
      return card(null, h("div", {},
        h("header", { class: "result-head", style: { padding: "12px 14px", borderBottom: "1px solid var(--border)" } },
          h("span", { class: "role-name" }, role), h("span", { class: "mono small muted" }, d.user), badge("ALLOWED", "b-ok"),
          d.masked.length ? badge(`${d.masked.length} masked`, "b-warn") : badge("nothing masked", "b-muted")),
        d.rows.length ? resultTable(d, 20) : empty("No rows (small-group suppression or row filter)."),
        h("div", { class: "result-meta" }, h("span", {}, `${d.row_count} rows`), h("span", {}, `${d.ms} ms server`), h("span", {}, `${Math.round(res.ms)} ms round-trip`),
          h("span", {}, d.request_id), h("span", {}, `policy ${d.policy_version}`),
          d.dp ? h("span", {}, `ε ${d.dp.epsilon} spent · ${d.dp.remaining} left today`) : null, d.risk ? h("span", {}, `risk ${d.risk}`) : null),
        h("details", { style: { padding: "0 12px 10px" } }, h("summary", {}, "Rewritten SQL sent to the database"), h("pre", { class: "sql mono" }, d.rewritten_sql))));
    }));
    const explainCard = card("Why each field looks the way it does", h("div", {}, h("div", { class: "body small muted" }, "Loading the effective policy for each role…")));
    const integrityCard = h("div", { class: "integrity-strip" }, h("span", { class: "muted" }, "Source integrity"), h("span", { class: "small muted" }, st.verify ? "verifying…" : "not requested"));
    out.replaceChildren(sql ? card("Query", h("div", { class: "body" }, h("pre", { class: "sql mono" }, sql))) : "", grid, explainCard, integrityCard);
    runBtn.disabled = false;
    // explanations per role (each role asks for its own policy, with its own token)
    const exTable = st.mode === "builder" ? st.table : guessTable(st.sql, tbls) || st.table;
    const ex = await Promise.all(roles.map(async (r) => ({ role: r, res: await api("GET", `/policy/explain?table=${encodeURIComponent(exTable)}`, undefined, await tokenFor(r)) })));
    const tabsRow = h("div", { class: "tabs", role: "tablist" });
    const exBody = h("div", {});
    const show = (i) => {
      tabsRow.replaceChildren(...ex.map((x, j) => h("button", { role: "tab", "aria-selected": String(i === j), onclick: () => show(j) }, x.role)));
      const x = ex[i];
      exBody.replaceChildren(x.res.ok ? h("div", {},
        h("div", { class: "body small muted" }, `Table ${x.res.data.table} · policy ${x.res.data.policy_version}` + (x.res.data.row_filter ? ` · row filter: ${x.res.data.row_filter}` : "") + (x.res.data.max_rows ? ` · row cap ${x.res.data.max_rows}` : "") + ". " + x.res.data.note),
        explainTable(x.res.data)) : errorBox(detail(x.res)));
    };
    show(0);
    explainCard.replaceChildren(h("header", {}, h("h2", {}, "Why each field looks the way it does"), h("span", { class: "spacer" }), h("span", { class: "small muted" }, exTable)), tabsRow, exBody);
    if (st.verify) verifyIntegrity(integrityCard);
  }
};

function guessTable(sql, tbls) {
  const m = /\bfrom\s+"?([a-z_][a-z0-9_]*)"?/i.exec(sql || "");
  return m && tbls.find((t) => t.table === m[1].toLowerCase()) ? m[1].toLowerCase() : null;
}

async function verifierToken() {
  if (can("integrity.verify")) return { token: S.token, who: S.me.user };
  if (S.meta.demo_mode) return { token: await demoToken("auditor"), who: "auditor.aud (demo auditor)" };
  return null;
}

async function verifyIntegrity(box) {
  const v = await verifierToken();
  if (!v) { box.replaceChildren(h("span", { class: "muted" }, "Source integrity"), h("span", { class: "small muted" }, "needs the integrity.verify capability")); return; }
  const r = await api("POST", "/integrity/verify", undefined, v.token);
  if (!r.ok) { box.replaceChildren(h("span", { class: "muted" }, "Source integrity"), badge("ERROR", "b-bad"), h("span", { class: "small" }, detail(r))); return; }
  const ok = r.data.status === "MATCH";
  box.replaceChildren(h("span", { class: "muted" }, "Source integrity"), badge(r.data.status, ok ? "b-ok" : "b-bad"),
    h("span", { class: "small" }, ok ? "Source mutation: NONE. Row counts, schemas and content digests equal the baseline." : "Source changed since the baseline: see Data integrity."),
    h("span", { class: "mono small muted" }, `${short(r.data.combined_after, 16)} · verified by ${v.who} · ${r.data.verified_at}`));
}

// ---------- discovery

PAGES.discovery = async (main) => {
  main.append(h("h1", {}, "PII discovery"),
    h("p", { class: "lede" }, "The scanner samples each column (values stay in memory, never displayed or logged), runs checksum validators (Luhn, Verhoeff, PAN, IBAN…) and a LightGBM classifier over 85 value statistics, and tags the column. Checksum hits can't be downgraded; uncertain columns are tagged for review and still masked."));
  if (!can("registry.read")) {
    const t = await tables();
    main.append(card("Columns visible to your role", h("div", { class: "body flush" }, h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ["Table", "Column", "Classification", "Your action"].map((x) => h("th", {}, x)))),
      h("tbody", {}, t.flatMap((x) => x.columns.map((c) => h("tr", {}, h("td", { class: "mono" }, x.table), h("td", { class: "mono" }, c.column), h("td", {}, tagBadge(c.tag)), h("td", {}, actionBadge(c.action)))))))))),
      h("p", { class: "small muted" }, "Detection evidence and rescans need the registry.read / scan.run capabilities (Auditor or Admin)."));
    return;
  }
  const [reg, tbl] = await Promise.all([api("GET", "/registry"), tables()]);
  if (!reg.ok) { main.append(errorBox(detail(reg))); return; }
  let tagged = reg.data.tagged;
  const counts = {};
  tbl.forEach((t) => t.columns.forEach((c) => { counts[c.tag] = (counts[c.tag] || 0) + 1; }));
  const filt = { tag: "", q: "", table: "" };
  const scanOut = h("div", {});
  const sample = h("input", { type: "number", min: 10, max: 5000, value: 200, style: { width: "90px" }, "aria-label": "Sample size per column" });
  const doScan = async (dry) => {
    if (!dry && !can("scan.run")) return toast("scan.run capability required (Admin)", "warn");
    scanOut.replaceChildren(loading(dry ? "Dry-run scan…" : "Scanning and applying…"));
    const r = await api("POST", "/scan", { sample_limit: +sample.value || 200, dry_run: dry });
    if (!r.ok) { scanOut.replaceChildren(errorBox(detail(r))); return; }
    scanOut.replaceChildren(h("div", { class: "row small" }, badge(r.data.dry_run ? "DRY RUN" : "APPLIED", r.data.dry_run ? "b-info" : "b-ok"),
      `${r.data.tagged.length} sensitive columns · ${r.data.tables.length} tables · ${r.data.ms} ms · ${r.data.scanned_at}`),
      h("p", { class: "small muted" }, r.data.limitations));
    if (!r.data.dry_run) { tagged = r.data.tagged; S.tablesCache = null; renderTable(); }
    toast(r.data.dry_run ? "Dry-run scan finished: registry unchanged" : "Rescan applied", "ok");
  };
  const tagSel = h("select", { "aria-label": "Filter by classification", onchange: (e) => { filt.tag = e.target.value; renderTable(); } },
    h("option", { value: "" }, "All classifications"), Object.keys(TAG_COLOR).map((t) => h("option", { value: t }, t)));
  const search = h("input", { type: "search", placeholder: "Search column or evidence", "aria-label": "Search", oninput: (e) => { filt.q = e.target.value.toLowerCase(); renderTable(); } });
  const tableList = h("div", { class: "stack" });
  const body = h("div", {});
  function renderTable() {
    const ev = Object.fromEntries(tagged.map((t) => [`${t.table}.${t.column}`, t]));
    const rows = tbl.flatMap((t) => t.columns.map((c) => ({ table: t.table, column: c.column, sql_type: c.sql_type, ...(ev[`${t.table}.${c.column}`] || { tag: c.tag }) })))
      .filter((r) => (!filt.tag || r.tag === filt.tag) && (!filt.table || r.table === filt.table) && (!filt.q || `${r.column} ${r.evidence || ""} ${r.kind || ""}`.toLowerCase().includes(filt.q)));
    tableList.replaceChildren(h("button", { class: `chip`, "aria-pressed": String(!filt.table), onclick: () => { filt.table = ""; renderTable(); } }, "All tables"),
      ...tbl.map((t) => h("button", { class: "chip", "aria-pressed": String(filt.table === t.table), onclick: () => { filt.table = t.table; renderTable(); } },
        `${t.table} · ${t.columns.filter((c) => c.tag !== "PUBLIC").length}/${t.columns.length}`)));
    body.replaceChildren(rows.length ? h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ["Table", "Column", "Type", "Classification", "Kind", "Confidence", "Source", "Evidence (no values)"].map((x) => h("th", {}, x)))),
      h("tbody", {}, rows.map((r) => h("tr", {}, h("td", { class: "mono" }, r.table), h("td", { class: "mono" }, r.column), h("td", { class: "mono muted" }, r.sql_type || "—"),
        h("td", {}, tagBadge(r.tag)), h("td", {}, r.kind || "—"),
        h("td", {}, r.confidence ? badge(r.confidence, r.confidence === "high" || r.confidence === "override" ? "b-ok" : r.confidence === "review" ? "b-warn" : "b-info") : "—"),
        h("td", { class: "small" }, r.source || "—"), h("td", { class: "small muted" }, r.evidence || "no PII signal in the sample"))))))
      : empty("No columns match the filter."));
  }
  renderTable();
  main.append(h("div", { class: "grid cols-3" },
    card("Classifications", h("div", { class: "body" }, hbars(Object.entries(counts).sort((a, b) => b[1] - a[1]), (t) => TAG_COLOR[t] || "#6b7684"))),
    card("Scan", h("div", { class: "body stack" }, h("label", {}, "Values sampled per column", sample),
      h("div", { class: "row" }, h("button", { onclick: () => doScan(true) }, "Dry-run scan"),
        h("button", { class: "primary", disabled: !can("scan.run"), title: can("scan.run") ? "" : "Admin only (scan.run)", onclick: () => doScan(false) }, "Rescan & apply")), scanOut)),
    card("How to read this", h("div", { class: "body small stack" },
      h("div", {}, tagBadge("PII_HIGH"), " direct identifiers (Aadhaar, PAN, SSN, phone, email)"),
      h("div", {}, tagBadge("FINANCIAL_CONFIDENTIAL"), " cards, IBANs, account numbers, balances"),
      h("div", {}, tagBadge("PII_MEDIUM"), " quasi-identifiers (name, DOB, address, PIN code)"),
      h("div", {}, tagBadge("PII_IN_TEXT"), " identifiers inside free text"),
      h("div", { class: "muted" }, "Sampling is probabilistic: no PII in the sample does not prove a column is clean. Force tags in policies/overrides.yaml.")))),
    h("div", { style: { height: "16px" } }),
    card("Column inventory", h("div", {}, h("div", { class: "body row" }, tagSel, search), h("div", { class: "body", style: { paddingTop: 0 } }, h("div", { class: "chips" }, tableList)), body)));
};

// ---------- policy studio

PAGES.policy = async (main) => {
  main.append(h("h1", {}, "Policy studio"),
    h("p", { class: "lede" }, "The enforced policy as a role × column matrix. Click a cell to change the rule for that role and classification. Changes are validated, versioned and audited; a change that weakens protection needs a reason and explicit confirmation. The YAML file remains the reviewed baseline (Reset returns to it)."));
  if (!can("policy.read")) {
    const r = await api("GET", "/policy");
    main.append(card("Your effective policy", h("div", { class: "body" }, h("dl", { class: "kv" },
      Object.entries(r.data.rules).flatMap(([t, a]) => [h("dt", {}, tagBadge(t)), h("dd", {}, actionBadge(a))])))), h("p", { class: "small muted" }, "The full matrix needs the policy.read capability."));
    return;
  }
  const [m, pol, hist] = await Promise.all([api("GET", "/policy/matrix"), api("GET", "/policy"), api("GET", "/policy/history")]);
  if (!m.ok) { main.append(errorBox(detail(m))); return; }
  const actions = pol.data.actions;
  let showPublic = false;
  const tableBox = h("div", {});
  const render = () => {
    const rows = m.data.rows.filter((r) => showPublic || r.tag !== "PUBLIC");
    tableBox.replaceChildren(h("div", { class: "table-wrap" }, h("table", { class: "matrix" },
      h("thead", {}, h("tr", {}, h("th", {}, "Column"), h("th", {}, "Classification"), m.data.roles.map((r) => h("th", { scope: "col" }, r)))),
      h("tbody", {}, rows.map((r) => h("tr", {}, h("td", { class: "mono" }, `${r.table}.${r.column}`), h("td", {}, tagBadge(r.tag)),
        m.data.roles.map((role) => h("td", {}, r.tag === "PUBLIC" ? actionBadge(r[role]) :
          h("button", { class: "cell", "aria-label": `${role} ${r.tag}: ${r[role]}. Edit rule`, onclick: () => editRule(role, r.tag, r[role], r) }, actionBadge(r[role]))))))))));
  };
  render();
  function editRule(role, tag, current, row) {
    const sel = h("select", {}, Object.entries(actions).map(([k, v]) => h("option", { value: k, selected: k === current }, `${k} · ${v.label}`)));
    const reason = h("input", { placeholder: "Reason (required when weakening)" });
    const confirm = h("input", { type: "checkbox" });
    const info = h("div", { class: "small" });
    const check = async () => {
      if (!can("policy.write")) { info.replaceChildren(badge("READ ONLY", "b-warn"), " Your role lacks policy.write; the server would refuse the change."); return null; }
      const r = await api("POST", "/policy/check", { role, tag, action: sel.value });
      if (!r.ok) { info.replaceChildren(errorBox(detail(r))); return null; }
      info.replaceChildren(h("div", { class: "row" }, r.data.weakening ? badge("WEAKENS PROTECTION", "b-warn") : badge("SAME OR STRICTER", "b-ok"),
        h("span", { class: "muted" }, `${r.data.current} → ${r.data.proposed}`)),
        ...r.data.warnings.map((w) => h("div", { class: "small", style: { color: "var(--warn)" } }, "⚠ " + w)));
      return r.data;
    };
    sel.addEventListener("change", check);
    const apply = async () => {
      const c = await check();
      if (!c) return;
      if (c.weakening && (!confirm.checked || !reason.value.trim())) { toast("Weakening needs a reason and the confirmation box", "warn"); return; }
      const r = await api("PUT", "/policy/rules", { role, tag, action: sel.value, reason: reason.value, confirm: confirm.checked });
      if (!r.ok) { toast(detail(r), "bad"); return; }
      closeDialog(); toast(r.data.changed ? `Rule updated · policy ${r.data.version}` : "No change", r.data.changed ? "ok" : "info");
      S.meta = (await api("GET", "/meta", undefined, null)).data; renderIdentity(); route();
    };
    openDialog(`Rule: ${role} × ${tag}`, [
      h("div", { class: "small muted" }, `Applies to every ${tag} column for ${role} (e.g. ${row.table}.${row.column}). Strictness: allow < partial < redact_text < hmac < aggregate < redact < deny.`),
      h("label", {}, "Action", sel), h("label", {}, "Reason", reason),
      h("label", { class: "inline" }, confirm, "I confirm this change may expose more data"), info],
      [h("button", { onclick: closeDialog }, "Cancel"), h("button", { class: "primary", disabled: !can("policy.write"), onclick: apply }, "Apply change")]);
    check();
  }
  const reset = async () => {
    openDialog("Reset policy to the file baseline?", h("div", {}, "All runtime rule changes are reverted. The reset is recorded in the history and the audit log."),
      [h("button", { onclick: closeDialog }, "Cancel"), h("button", { class: "danger", onclick: async () => {
        const r = await api("POST", "/policy/reset"); closeDialog();
        toast(r.ok ? `Policy reset · ${r.data.version_after}` : detail(r), r.ok ? "ok" : "bad");
        S.meta = (await api("GET", "/meta", undefined, null)).data; renderIdentity(); route();
      } }, "Reset")]);
  };
  main.append(card(`Role × column matrix · ${m.data.policy_version}`, tableBox,
      h("label", { class: "inline small" }, h("input", { type: "checkbox", onchange: (e) => { showPublic = e.target.checked; render(); } }), "show public columns"),
      can("policy.write") ? h("button", { class: "small danger", onclick: reset }, "Reset to file") : badge("read only", "b-muted")),
    h("div", { style: { height: "16px" } }),
    h("div", { class: "grid cols-2" },
      card("Masking actions (strictness order)", h("div", { class: "table-wrap" }, h("table", {}, h("tbody", {},
        Object.entries(actions).sort((a, b) => a[1].strictness - b[1].strictness).map(([k, v]) => h("tr", {}, h("td", {}, actionBadge(k)), h("td", {}, h("b", {}, v.label), h("div", { class: "small muted" }, v.detail)))))))),
      card("Change history", hist.ok && hist.data.history.length ? h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, ["When", "Actor", "Change", "Reason", "Version"].map((x) => h("th", {}, x)))),
        h("tbody", {}, hist.data.history.slice().reverse().map((e) => h("tr", {}, h("td", { class: "mono small" }, fmtTime(e.ts)), h("td", { class: "mono" }, e.actor),
          h("td", {}, e.change === "reset" ? "reset to file" : [`${e.role} / ${e.tag}: `, actionBadge(e.from), " → ", actionBadge(e.to)], e.weakening ? badge("weakening", "b-warn") : null),
          h("td", { class: "small" }, e.reason || "—"), h("td", { class: "mono small" }, e.version_after))))))
        : empty("No runtime changes: the policy equals the reviewed YAML file."))));
};

// ---------- roles

PAGES.roles = async (main) => {
  main.append(h("h1", {}, "Role explorer"), h("p", { class: "lede" }, "What each role can see and do. Capabilities gate the non-data endpoints; masking rules gate every value. Nothing here can unmask data except the rules themselves."));
  const r = await api("GET", "/roles");
  if (!r.ok) { main.append(errorBox(detail(r))); return; }
  const roles = r.data.roles;
  main.append(h("div", { class: "grid cols-2" }, roles.map((x) => card(x.label || x.role, h("div", { class: "body stack" },
    h("div", { class: "muted" }, x.description || ""),
    x.rules ? h("div", {}, h("h3", {}, "Masking rules"), h("dl", { class: "kv" }, Object.entries(x.rules).flatMap(([t, a]) => [h("dt", {}, tagBadge(t)), h("dd", {}, actionBadge(a))]))) : h("div", { class: "small muted" }, "Rules hidden: needs policy.read."),
    x.capabilities ? h("div", {}, h("h3", {}, "Capabilities"), h("div", { class: "row" }, x.capabilities.map((c) => badge(c, "b-info")))) : null,
    x.rules ? h("dl", { class: "kv" }, h("dt", {}, "Row filters"), h("dd", {}, Object.entries(x.row_filters || {}).map(([t, f]) => `${t}: ${f}`).join("; ") || "none"),
      h("dt", {}, "Row cap"), h("dd", {}, x.max_rows || "none"), h("dt", {}, "Min group size"), h("dd", {}, x.min_group_size || "none")) : null),
    x.role === (S.me && S.me.role) ? badge("you", "b-ok") : null))));
  const withRules = roles.filter((x) => x.rules);
  if (withRules.length > 1) {
    const tags = [...new Set(withRules.flatMap((x) => Object.keys(x.rules)))];
    main.append(h("div", { style: { height: "16px" } }), card("Compare roles", h("div", { class: "table-wrap" }, h("table", { class: "matrix" },
      h("thead", {}, h("tr", {}, h("th", {}, "Classification"), h("th", {}, ""), withRules.map((x) => h("th", {}, x.role)))),
      h("tbody", {}, tags.map((t) => h("tr", {}, h("td", {}, tagBadge(t)), h("td", {}), withRules.map((x) => h("td", {}, actionBadge(x.rules[t] || "deny"))))),
        h("tr", {}, h("td", {}, "capabilities"), h("td", {}), withRules.map((x) => h("td", { class: "mono" }, String(x.capabilities.length)))))))));
  }
};

// ---------- audit

PAGES.audit = async (main) => {
  main.append(h("h1", {}, "Audit explorer"), h("p", { class: "lede" }, "Every query, refusal, denial, policy change and integrity check, append-only and hash-chained. SQL is stored as a fingerprint with literals replaced by ?, so personal data never enters the log."));
  if (!can("audit.read")) { main.append(card(null, needCap("audit.read"))); return; }
  const f = { user: "", role: "", decision: "", q: "", request_id: "", n: 100 };
  const inputs = {
    user: h("input", { placeholder: "user", "aria-label": "User" }),
    role: h("select", { "aria-label": "Role" }, h("option", { value: "" }, "any role"), ...["admin", "support", "analyst", "auditor", "operator"].map((r) => h("option", { value: r }, r))),
    decision: h("select", { "aria-label": "Decision" }, h("option", { value: "" }, "any decision"), ...["allow", "reject", "denied", "blocked", "error", "policy_change", "integrity_verify", "integrity_proof", "integrity_baseline", "scan", "unblock"].map((r) => h("option", { value: r }, r))),
    q: h("input", { type: "search", placeholder: "search SQL fingerprint / reason", "aria-label": "Search" }),
    request_id: h("input", { placeholder: "req-…", "aria-label": "Request id", class: "mono" }),
  };
  const chain = h("span", {});
  const box = h("div", {}, loading());
  const more = h("button", { class: "small", onclick: () => { f.n += 100; load(); } }, "Load 100 more");
  async function load() {
    Object.keys(inputs).forEach((k) => { f[k] = inputs[k].value.trim(); });
    const qs = new URLSearchParams(Object.entries(f).filter(([, v]) => v !== "")).toString();
    box.replaceChildren(loading());
    const r = await api("GET", `/audit?${qs}`);
    if (!r.ok) { box.replaceChildren(errorBox(detail(r))); return; }
    chain.replaceChildren(okBadge(r.data.chain_valid, "CHAIN INTACT", "CHAIN BROKEN"));
    const entries = r.data.entries.slice().reverse();
    if (!entries.length) { box.replaceChildren(empty("No events match these filters.")); return; }
    box.replaceChildren(h("div", { class: "table-wrap", style: { maxHeight: "640px" } }, h("table", {},
      h("thead", {}, h("tr", {}, ["Time", "Request", "Channel", "User", "Role", "Decision", "Policy", "What", "Masked", "Rows", "ms", "Risk"].map((x) => h("th", { scope: "col" }, x)))),
      h("tbody", {}, entries.map((e) => {
        const tr = h("tr", { class: "clickable", tabindex: 0, "aria-expanded": "false" },
          h("td", { class: "mono small" }, fmtTime(e.ts)), h("td", { class: "mono small" }, e.request_id || "—"), h("td", { class: "small" }, e.channel || "—"),
          h("td", { class: "mono" }, e.user || "—"), h("td", {}, e.role || "—"), h("td", {}, decisionBadge(e.decision)), h("td", { class: "mono small muted" }, e.policy_version || "—"),
          h("td", { class: "mono small" }, (e.sql || e.target || "").slice(0, 80), e.reason ? h("div", { class: "small", style: { color: "var(--warn)" } }, e.reason.slice(0, 120)) : null),
          h("td", { class: "small" }, e.masked ? e.masked.length : "—"), h("td", { class: "small" }, e.rows ?? "—"), h("td", { class: "small" }, e.ms ?? "—"), h("td", { class: "small" }, e.risk ?? "—"));
        const toggle = () => {
          const open = tr.nextSibling && tr.nextSibling.classList && tr.nextSibling.classList.contains("detail-row");
          if (open) { tr.nextSibling.remove(); tr.setAttribute("aria-expanded", "false"); tr.classList.remove("expanded"); return; }
          tr.after(h("tr", { class: "detail-row" }, h("td", { colspan: 12 }, h("pre", { class: "sql mono" }, JSON.stringify(e, null, 2)))));
          tr.setAttribute("aria-expanded", "true"); tr.classList.add("expanded");
        };
        tr.addEventListener("click", toggle); tr.addEventListener("keydown", (ev) => (ev.key === "Enter" || ev.key === " ") && (ev.preventDefault(), toggle()));
        return tr;
      })))), h("div", { class: "body row small muted" }, `${entries.length} events (newest first)`, more));
  }
  Object.values(inputs).forEach((i) => i.addEventListener("keydown", (e) => e.key === "Enter" && load()));
  main.append(card("Events", h("div", {}, h("div", { class: "body row" }, ...Object.values(inputs),
    h("button", { class: "primary small", onclick: load }, "Apply filters"),
    h("button", { class: "small ghost", onclick: () => { Object.values(inputs).forEach((i) => { i.value = ""; }); f.n = 100; load(); } }, "Clear")), box), chain));
  load();
};

// ---------- integrity

PAGES.integrity = async (main) => {
  main.append(h("h1", {}, "Data integrity"),
    h("p", { class: "lede" }, "Proof that masking never modifies stored records. A baseline records, per table, the row count, a SHA-256 of the schema and a SHA-256 over the sorted canonical-JSON encoding of every row. Verification recomputes them through a separate privileged read."));
  if (!can("integrity.verify")) { main.append(card(null, needCap("integrity.verify"))); return; }
  const [st, hist] = await Promise.all([api("GET", "/integrity/status"), api("GET", "/integrity/history?n=15")]);
  if (!st.ok) { main.append(errorBox(detail(st))); return; }
  const b = st.data.baseline;
  const result = h("div", {}, empty("Run a verification or the full proof."));
  const sql = h("input", { class: "mono", value: "SELECT * FROM users ORDER BY id LIMIT 5", style: { flex: "1", minWidth: "260px" }, "aria-label": "Proof query" });
  const verify = async () => {
    result.replaceChildren(loading("Hashing source tables…"));
    const r = await api("POST", "/integrity/verify");
    if (!r.ok) { result.replaceChildren(errorBox(detail(r))); return; }
    result.replaceChildren(verifyView(r.data));
  };
  const proof = async () => {
    result.replaceChildren(loading("Digest → same query as every role → write attempts → digest…"));
    const r = await api("POST", "/integrity/proof", { sql: sql.value });
    if (!r.ok) { result.replaceChildren(errorBox(detail(r))); return; }
    const p = r.data;
    result.replaceChildren(h("div", { class: "stack" },
      h("div", { class: "row" }, okBadge(p.status === "PASS"), h("b", {}, p.status === "PASS" ? "Source mutation: NONE" : "Source mutation DETECTED"), h("span", { class: "mono small muted" }, `${short(p.before, 20)} → ${short(p.after, 20)}`)),
      h("h3", {}, "1 · Same query as every role"),
      h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, ["Role", "Result", "Rows", "Masked columns", "Request"].map((x) => h("th", {}, x)))),
        h("tbody", {}, p.queries.map((q) => h("tr", {}, h("td", {}, q.role), h("td", {}, badge(q.status, q.status === "ALLOWED" ? "b-ok" : "b-warn")), h("td", {}, q.rows ?? "—"), h("td", {}, q.masked ?? "—"), h("td", { class: "mono small" }, q.request_id || q.reason || "—")))))),
      h("h3", {}, "2 · Write attempts through the gateway"),
      h("div", { class: "table-wrap" }, h("table", {}, h("tbody", {}, p.unauthorized_attempts.map((a) => h("tr", {}, h("td", {}, a.attempt), h("td", {}, badge(a.status, a.status === "REJECTED" ? "b-ok" : "b-bad")), h("td", { class: "small muted" }, a.reason || "")))))),
      h("h3", {}, "3 · Digest after"), verifyView({ status: p.status === "PASS" ? "MATCH" : "CHANGED", tables: p.tables })));
  };
  const rebaseline = () => {
    const reason = h("input", { placeholder: "Why is the current data the new reference?" });
    openDialog("Record a new baseline?", [h("div", { class: "small" }, "Future verifications compare against the data as it is now. Do this only when the data is known-good and quiet (no concurrent writes)."), h("label", {}, "Reason", reason)],
      [h("button", { onclick: closeDialog }, "Cancel"), h("button", { class: "primary", onclick: async () => {
        if (!reason.value.trim()) return toast("Give a reason", "warn");
        const r = await api("POST", "/integrity/baseline", { reason: reason.value }); closeDialog();
        toast(r.ok ? "Baseline recorded" : detail(r), r.ok ? "ok" : "bad"); if (r.ok) route();
      } }, "Record baseline")]);
  };
  main.append(h("div", { class: "grid cols-2" },
    card("Baseline", b ? h("div", { class: "stack" }, h("div", { class: "body" }, h("dl", { class: "kv" },
        h("dt", {}, "Taken"), h("dd", {}, b.taken_at), h("dt", {}, "By"), h("dd", {}, `${b.recorded_by || "system"}${b.reason ? " · " + b.reason : ""}`),
        h("dt", {}, "Combined digest"), h("dd", {}, b.combined_sha256))),
      h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, ["Table", "Rows", "Columns", "Schema SHA-256", "Content SHA-256"].map((x) => h("th", {}, x)))),
        h("tbody", {}, Object.entries(b.tables).map(([t, v]) => h("tr", {}, h("td", { class: "mono" }, t), h("td", {}, v.rows), h("td", {}, v.columns), h("td", { class: "mono small" }, short(v.schema_sha256, 16)), h("td", { class: "mono small" }, short(v.content_sha256, 16)))))))) : empty("No baseline recorded."),
      can("integrity.baseline") ? h("button", { class: "small", onclick: rebaseline }, "Record new baseline") : badge("baseline: admin only", "b-muted")),
    card("Verify", h("div", { class: "body stack" },
      h("div", { class: "row" }, h("button", { class: "primary", onclick: verify }, "Verify now"), h("span", { class: "small muted" }, "recompute and compare with the baseline")),
      h("div", { class: "row" }, sql, h("button", { onclick: proof }, "Run full proof")),
      h("p", { class: "small muted" }, "Limits: the digest covers source tables only (not MaskGuard's own audit, policy or registry files, which change by design and have their own checks). A mismatch means the data changed, not necessarily tampering: legitimate application writes also change it. Each check reads whole tables, so it is meant for audits and demos, not every query.")))),
    h("div", { style: { height: "16px" } }), card("Result", h("div", { class: "body" }, result)),
    h("div", { style: { height: "16px" } }),
    card("Verification history", hist.ok && hist.data.history.length ? h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, ["When", "Actor", "Status", "Changed tables"].map((x) => h("th", {}, x)))),
      h("tbody", {}, hist.data.history.slice().reverse().map((e) => h("tr", {}, h("td", { class: "mono small" }, e.verified_at), h("td", { class: "mono" }, e.actor), h("td", {}, badge(e.status, e.status === "MATCH" ? "b-ok" : "b-bad")), h("td", {}, (e.changed || []).join(", ") || "—"))))))
      : empty("No verifications yet.")));
};

function verifyView(r) {
  if (r.status === "NO_BASELINE") return empty("No baseline recorded yet.");
  return h("div", { class: "stack" },
    h("div", { class: "row" }, badge(r.status, r.status === "MATCH" ? "b-ok" : "b-bad"), r.verified_at ? h("span", { class: "small muted" }, `baseline ${r.baseline_taken_at} → verified ${r.verified_at}`) : null),
    h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, ["Table", "Status", "Rows before", "Rows after", "Schema", "Content digest"].map((x) => h("th", {}, x)))),
      h("tbody", {}, r.tables.map((t) => h("tr", {}, h("td", { class: "mono" }, t.table), h("td", {}, badge(t.status, t.status === "MATCH" ? "b-ok" : "b-bad")),
        h("td", {}, t.rows_before ?? "—"), h("td", {}, t.rows_after ?? "—"), h("td", {}, t.schema_changed ? badge("changed", "b-bad") : "same"),
        h("td", { class: "mono small" }, t.content_changed ? [short(t.digest_before, 10), " → ", short(t.digest_after, 10)] : short(t.digest_after, 20))))))));
}

// ---------- API lab

const EXAMPLES = {
  "POST /query": { sql: "SELECT name, ssn, email FROM users ORDER BY id LIMIT 3" },
  "POST /query/table": { table: "accounts", columns: ["credit_card", "balance", "status"], limit: 5 },
  "POST /demo/compare": { sql: "SELECT ssn FROM users ORDER BY id LIMIT 2", roles: ["admin", "support", "analyst"] },
  "POST /auth/login": { username: "support.sam", password: "" },
  "POST /auth/demo": { role: "support" },
  "POST /scan": { dry_run: true, sample_limit: 100 },
  "POST /policy/check": { role: "support", tag: "PII_HIGH", action: "hmac" },
  "PUT /policy/rules": { role: "support", tag: "PII_HIGH", action: "hmac", reason: "", confirm: false },
  "POST /integrity/proof": { sql: "SELECT * FROM users ORDER BY id LIMIT 5" },
  "POST /integrity/baseline": { reason: "" },
};

PAGES.api = async (main) => {
  main.append(h("h1", {}, "API lab"), h("p", { class: "lede" }, "Try any endpoint as your current identity. The server decides what you get: the response here is exactly what your token is authorised to see. Tokens are never shown; cURL examples use $MASKGUARD_TOKEN."));
  const spec = await api("GET", "/openapi.json", undefined, null);
  if (!spec.ok) { main.append(errorBox("Could not load the OpenAPI document")); return; }
  const eps = [];
  Object.entries(spec.data.paths).forEach(([p, ops]) => Object.entries(ops).forEach(([m, op]) => eps.push({ method: m.toUpperCase(), path: p, op })));
  const groups = {};
  eps.forEach((e) => { const t = (e.op.tags || ["other"])[0]; (groups[t] = groups[t] || []).push(e); });
  const list = h("div", { class: "stack", style: { maxHeight: "640px", overflow: "auto" } });
  const panel = h("div", {});
  let cur = null;
  const pick = (e) => {
    cur = e;
    const key = `${e.method} ${e.path}`;
    const params = (e.op.parameters || []).filter((p) => p.in === "query");
    const pathParams = (e.op.parameters || []).filter((p) => p.in === "path");
    const pathInput = h("input", { class: "mono", value: e.path + (params.length ? "?" + params.filter((p) => p.required || ["table", "n"].includes(p.name)).map((p) => `${p.name}=${p.name === "table" ? "users" : p.name === "n" ? "20" : ""}`).join("&") : ""), style: { flex: "1" }, "aria-label": "Path" });
    const bodyIn = h("textarea", { "aria-label": "JSON body", style: { minHeight: "130px" } }, e.op.requestBody ? JSON.stringify(EXAMPLES[key] || {}, null, 2) : "");
    const resBox = h("div", {});
    const curl = h("code", {});
    const updateCurl = () => {
      const b = bodyIn.value.trim();
      curl.textContent = `curl -s -X ${e.method} "${location.origin}${pathInput.value}" -H "Authorization: Bearer $MASKGUARD_TOKEN"` + (b && e.op.requestBody ? ` -H "Content-Type: application/json" -d '${b.replace(/\s+/g, " ").replace(/'/g, "'\\''")}'` : "");
    };
    pathInput.addEventListener("input", updateCurl); bodyIn.addEventListener("input", updateCurl); updateCurl();
    const send = async () => {
      let body;
      if (e.op.requestBody && bodyIn.value.trim()) { try { body = JSON.parse(bodyIn.value); } catch { toast("Body is not valid JSON", "warn"); return; } }
      resBox.replaceChildren(loading("Sending…"));
      const r = await api(e.method, pathInput.value, body);
      const decision = r.status === 0 ? ["UNREACHABLE", "b-bad"] : r.ok ? ["ALLOWED", "b-ok"] : r.status === 401 ? ["UNAUTHENTICATED", "b-bad"] : r.status === 403 ? ["DENIED (capability)", "b-bad"] : r.status === 400 ? ["REFUSED (firewall / validation)", "b-warn"] : r.status === 409 ? ["NEEDS CONFIRMATION", "b-warn"] : [`HTTP ${r.status}`, "b-warn"];
      const txt = typeof r.data === "string" ? r.data : JSON.stringify(r.data, null, 2);
      resBox.replaceChildren(h("div", { class: "row" }, badge(String(r.status), r.ok ? "b-ok" : "b-bad"), badge(decision[0], decision[1]), h("span", { class: "mono small muted" }, `${Math.round(r.ms)} ms`), r.rid ? h("span", { class: "mono small muted" }, r.rid) : null),
        h("pre", { class: "sql mono", style: { maxHeight: "420px" } }, txt.length > 20000 ? txt.slice(0, 20000) + "\n… truncated" : txt));
    };
    panel.replaceChildren(card(`${e.method} ${e.path}`, h("div", { class: "body stack" },
      h("div", { class: "small muted" }, e.op.summary || "", e.op.description ? h("div", {}, e.op.description) : null),
      pathParams.length ? h("div", { class: "small muted" }, `Path parameters: ${pathParams.map((p) => p.name).join(", ")} (edit the path)`) : null,
      h("div", { class: "row" }, badge(e.method, "b-info"), pathInput, h("button", { class: "primary", onclick: send }, "Send")),
      e.op.requestBody ? h("label", {}, "JSON body", bodyIn) : null,
      h("div", { class: "copy-row" }, curl, h("button", { class: "small", onclick: async () => {
        try { await navigator.clipboard.writeText(curl.textContent); toast("cURL copied", "ok"); } catch { toast("Copy failed: select the text and copy manually", "warn"); }
      } }, "Copy cURL")), resBox)));
    list.querySelectorAll("button").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.key === key)));
  };
  Object.entries(groups).forEach(([g, es]) => list.append(h("h3", { style: { marginTop: "8px" } }, g), ...es.map((e) =>
    h("button", { class: "chip", "data-key": `${e.method} ${e.path}`, style: { justifyContent: "flex-start", borderRadius: "8px" }, onclick: () => pick(e) }, h("span", { class: "mono small", style: { width: "44px", display: "inline-block" } }, e.method), h("span", { class: "mono small" }, e.path)))));
  main.append(h("div", { class: "row", style: { marginBottom: "14px" } },
    h("a", { class: "btn small", href: "/docs", target: "_blank", rel: "noopener" }, "OpenAPI / Swagger ↗"),
    h("a", { class: "btn small", href: "/openapi.json", target: "_blank", rel: "noopener" }, "openapi.json ↗"),
    h("a", { class: "btn small", href: "/postman", download: "Smart-Data-Masking.postman_collection.json" }, "Download Postman collection")),
    h("div", { class: "pg" }, card("Endpoints", h("div", { class: "body" }, list)), panel));
  pick(eps.find((e) => e.path === "/query") || eps[0]);
};

// ---------- CLI guide

PAGES.cli = async (main) => {
  const cmd = (c, d) => h("tr", {}, h("td", {}, h("div", { class: "copy-row" }, h("code", {}, c), copyBtn(c))), h("td", { class: "small" }, d));
  main.append(h("h1", {}, "CLI guide"), h("p", { class: "lede" }, "The maskguard CLI uses the same engine as this dashboard: in-process by default, or through this API with --api URL. Results go to stdout (add --json), diagnostics to stderr, with stable exit codes."),
    h("div", { class: "grid cols-2" },
      card("Start", h("div", { class: "body stack" },
        h("div", { class: "small muted" }, "Linux / macOS"),
        h("div", { class: "term" }, h("span", { class: "p" }, "$ "), "uv sync\n", h("span", { class: "p" }, "$ "), "export MASKGUARD_HMAC_KEY=dev-only-key\n", h("span", { class: "p" }, "$ "), "uv run maskguard            ", h("span", { class: "c" }, "# interactive console")),
        h("div", { class: "small muted" }, "Windows PowerShell"),
        h("div", { class: "term" }, h("span", { class: "p" }, "PS> "), "uv sync\n", h("span", { class: "p" }, "PS> "), "$env:MASKGUARD_HMAC_KEY=\"dev-only-key\"\n", h("span", { class: "p" }, "PS> "), "uv run maskguard"))),
      card("Exit codes", h("div", { class: "table-wrap" }, h("table", {}, h("tbody", {},
        [["0", "ok"], ["1", "unexpected error"], ["2", "usage error"], ["3", "denied: policy, firewall or credentials"], ["4", "unavailable: database or API"], ["5", "integrity check failed"], ["6", "security regression failed"]]
          .map(([c, d]) => h("tr", {}, h("td", { class: "mono" }, c), h("td", {}, d)))))))),
    h("div", { style: { height: "16px" } }),
    card("Command reference", h("div", { class: "table-wrap" }, h("table", {}, h("tbody", {},
      cmd("maskguard doctor", "Check dependencies, keys, database, model, policy, audit chain, integrity baseline"),
      cmd("maskguard status --json", "Engine status (real checks only)"),
      cmd("maskguard db inspect", "Tables, row counts, per-column classification (no values)"),
      cmd("maskguard scan --sample-limit 500 --dry-run", "Classify without applying; sample values are never printed"),
      cmd("maskguard pii list", "Every sensitive column with evidence"),
      cmd("maskguard roles show analyst", "Rules, row filters, caps and capabilities of one role"),
      cmd("maskguard policy explain --role analyst --table users", "Why each field is masked, with synthetic examples"),
      cmd("maskguard query --role support --table accounts -n 5 --explain", "Query builder as the Support demo identity"),
      cmd("maskguard query -u support.sam \"SELECT ssn FROM users LIMIT 3\"", "Any SELECT as a real user (password prompted)"),
      cmd("maskguard compare --table users --roles admin,support,analyst", "Same query, several roles, side by side"),
      cmd("maskguard audit list --decision reject", "Filtered audit trail"),
      cmd("maskguard integrity proof", "Digest → every role → write attempts → digest (PASS/FAIL)"),
      cmd("maskguard test", "Attack suite per role + audit chain + integrity proof; exit 6 on failure"),
      cmd("maskguard --api http://127.0.0.1:8000 compare \"SELECT ssn FROM users LIMIT 2\"", "Same command through the REST API"),
      cmd("maskguard serve", "API + this dashboard"),
      cmd("maskguard proxy", "PostgreSQL wire protocol: psql \"host=localhost port=6543 user=support.sam\""))))),
    h("div", { style: { height: "16px" } }),
    card("Example output (illustrative, from the synthetic dataset)", h("div", { class: "body" }, h("div", { class: "term" },
      h("span", { class: "p" }, "$ "), "maskguard compare \"SELECT name, ssn FROM users ORDER BY id LIMIT 1\" --roles support,analyst\n",
      "SUPPORT · support.sam ─────────────────\n name           ssn [PARTIAL]\n Matthew Rana   XXX-XX-4078\n", h("span", { class: "c" }, "1 rows · 4.6 ms · request req-… · policy v1-…\n"),
      "ANALYST · analyst.ali ─────────────────\n name [REDACT]   ssn [HMAC]\n REDACTED        680bd690cfe1edc6\n", h("span", { class: "c" }, "1 rows · 4.0 ms · request req-… · policy v1-…")))));
};

// ---------- settings / diagnostics

PAGES.settings = async (main) => {
  main.append(h("h1", {}, "Diagnostics"), h("p", { class: "lede" }, "Safe configuration and dependency status. Secrets, keys, tokens and database credentials are never sent to the browser: only whether they are set."));
  const [ready, diag] = await Promise.all([api("GET", "/ready", undefined, null), can("policy.read") ? api("GET", "/diagnostics") : null]);
  const compact = h("input", { type: "checkbox", checked: prefs.get("compact", false), onchange: (e) => { prefs.set("compact", e.target.checked); applyPrefs(); } });
  const motion = h("input", { type: "checkbox", checked: prefs.get("reduceMotion", false), onchange: (e) => { prefs.set("reduceMotion", e.target.checked); applyPrefs(); } });
  main.append(h("div", { class: "grid cols-2" },
    card("Readiness", h("div", { class: "body" }, h("div", { class: "checks" }, Object.entries((ready.data && ready.data.checks) || {}).map(([k, v]) => h("div", { class: "check" }, h("span", {}, k.replace(/_/g, " ")), okBadge(v.ok), h("span", { class: "detail" }, Object.entries(v).filter(([x]) => x !== "ok").map(([x, y]) => `${x}=${y}`).join("  "))))))),
    card("Configuration", diag ? (diag.ok ? h("div", { class: "body" }, h("dl", { class: "kv" }, Object.entries(diag.data).flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, typeof v === "object" ? JSON.stringify(v) : String(v))]))) : errorBox(detail(diag))) : needCap("policy.read")),
    card("This session", h("div", { class: "body stack" }, h("dl", { class: "kv" },
      h("dt", {}, "Identity"), h("dd", {}, S.me ? `${S.me.user} (${S.me.role})` : "signed out"),
      h("dt", {}, "Capabilities"), h("dd", {}, S.me ? S.me.capabilities.join(", ") : "—"),
      h("dt", {}, "Token storage"), h("dd", {}, "this tab only (sessionStorage); cleared by Sign out"),
      h("dt", {}, "API version"), h("dd", {}, S.meta.version), h("dt", {}, "Uptime"), h("dd", {}, `${S.meta.uptime_s} s at page load`)))),
    card("Display", h("div", { class: "body stack" }, h("label", { class: "inline" }, compact, "Compact tables"), h("label", { class: "inline" }, motion, "Reduce motion (also follows your OS setting)")))));
};

// ------------------------------------------------------------------ router + boot

function applyPrefs() {
  document.body.classList.toggle("compact", !!prefs.get("compact", false));
  document.body.classList.toggle("reduce-motion", !!prefs.get("reduceMotion", false));
}

let routeSeq = 0;
async function route() {
  const page = (location.hash.replace(/^#\//, "") || "overview").split("?")[0];
  const fn = PAGES[page] ? page : "overview";
  document.querySelectorAll("#nav a").forEach((a) => (a.dataset.page === fn ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current")));
  $("#crumbs").replaceChildren(TITLES[fn], h("small", {}, S.me ? `as ${S.me.user}` : ""));
  document.title = `${TITLES[fn]} · MaskGuard`;
  $(".side").classList.remove("open"); $("#menu-btn").setAttribute("aria-expanded", "false");
  tipHide();  // a chart tooltip must not outlive its page
  const main = $("#main");
  const seq = ++routeSeq;
  const frag = h("div", {});
  main.replaceChildren(loading());
  if (!S.me) {
    main.replaceChildren(card("Sign in to continue", h("div", { class: "body stack" },
      h("div", {}, "MaskGuard authorises every request on the server. Choose an identity:"),
      S.meta && S.meta.demo_mode ? h("div", { class: "chips" }, S.meta.demo_identities.map((d) => h("button", { class: "chip", onclick: () => signInDemo(d.role) }, `${d.role} · ${d.user}`))) : null,
      h("div", {}, h("button", { class: "primary", onclick: openSignIn }, "Sign in with a username")))));
    return;
  }
  try { await PAGES[fn](frag); }
  catch (e) { frag.append(errorBox(`Something went wrong: ${e.message}`)); }
  if (seq === routeSeq) { main.replaceChildren(frag); main.focus({ preventScroll: true }); }
}

async function boot() {
  applyPrefs();
  $("#menu-btn").addEventListener("click", () => { const o = $(".side").classList.toggle("open"); $("#menu-btn").setAttribute("aria-expanded", String(o)); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") { $(".side").classList.remove("open"); tipHide(); } });
  const meta = await api("GET", "/meta", undefined, null);
  if (!meta.ok) { $("#main").replaceChildren(errorBox("The MaskGuard API is not reachable. Start it with: maskguard serve")); return; }
  S.meta = meta.data;
  const ready = await api("GET", "/ready", undefined, null);
  S.ready = ready.data;
  const saved = store.get("mg.token", null);
  if (!(saved && await useToken(saved)) && S.meta.demo_mode) await signInDemo("admin").catch(() => {});
  renderIdentity();
  window.addEventListener("hashchange", route);
  route();
}
boot();
