"""Offline triage HTML report — single-file, no CDN required."""

from __future__ import annotations

import html
import json
from pathlib import Path


def render_triage_html(report: dict) -> str:
    findings = report.get("findings") or []
    data_json = json.dumps(findings, ensure_ascii=False)
    data_json = data_json.replace("</", "<\\/")
    target = html.escape(str(report.get("target", "")))
    stamp = html.escape(str(report.get("timestamp", "")))
    n = int(report.get("findings_count") or len(findings))
    tiers = report.get("tier_counts") or {}
    tier_s = html.escape(", ".join(f"{k}:{v}" for k, v in sorted(tiers.items())) or "—")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>ShardGuard Report</title>
<style>
:root {{
  --bg:#0c0d0f; --surface:#14161a; --border:#2a2e36; --text:#e8eaed; --muted:#8b919a;
  --accent:#d97706; --crit:#ef4444; --high:#f97316; --med:#eab308; --low:#64748b; --ok:#22c55e;
}}
* {{ box-sizing:border-box; }}
html,body {{ height:100%; margin:0; background:var(--bg); color:var(--text);
  font:14px/1.45 "Segoe UI", system-ui, sans-serif; }}
button,input,select {{ font:inherit; }}
.topbar {{ display:flex; align-items:center; gap:12px; padding:12px 16px; border-bottom:1px solid var(--border);
  background:var(--surface); position:sticky; top:0; z-index:5; flex-wrap:wrap; }}
.brand {{ font-weight:700; letter-spacing:0.02em; color:var(--accent); }}
.meta {{ color:var(--muted); font-size:12px; flex:1; min-width:160px; }}
.actions {{ display:flex; gap:8px; flex-wrap:wrap; }}
.btn {{ background:#1c1f26; color:var(--text); border:1px solid var(--border); border-radius:5px;
  padding:6px 12px; cursor:pointer; }}
.btn:hover {{ border-color:var(--accent); }}
.btn:focus-visible {{ outline:2px solid var(--accent); outline-offset:2px; }}
.btn-accent {{ background:var(--accent); color:#111; border-color:var(--accent); font-weight:600; }}
.shell {{ display:grid; grid-template-columns:220px 1fr 340px; height:calc(100% - 52px); }}
@media (max-width:960px) {{ .shell {{ grid-template-columns:1fr; height:auto; }} .pane {{ max-height:40vh; }} }}
.pane {{ border-right:1px solid var(--border); overflow:auto; }}
.pane:last-child {{ border-right:none; border-left:1px solid var(--border); }}
.pane h2 {{ margin:0; padding:12px 14px; font-size:12px; text-transform:uppercase; letter-spacing:0.06em;
  color:var(--muted); border-bottom:1px solid var(--border); }}
.filters {{ display:flex; flex-wrap:wrap; gap:6px; padding:10px 12px; border-bottom:1px solid var(--border); }}
.chip {{ border:1px solid var(--border); border-radius:999px; padding:3px 10px; background:transparent;
  color:var(--muted); cursor:pointer; font-size:12px; }}
.chip.on {{ border-color:var(--accent); color:var(--text); background:#1a1408; }}
#search {{ width:100%; margin:8px 12px; max-width:calc(100% - 24px); background:#0c0d0f; border:1px solid var(--border);
  border-radius:5px; color:var(--text); padding:8px 10px; }}
.file {{ padding:8px 14px; cursor:pointer; border-bottom:1px solid #1a1d22; font-size:12px; color:var(--muted); }}
.file:hover,.file.active {{ background:#1a1d24; color:var(--text); }}
.dot {{ display:inline-block; width:7px; height:7px; border-radius:50%; margin-right:6px; background:var(--low); }}
.dot.P0,.dot.CRITICAL {{ background:var(--crit); }}
.dot.P1,.dot.HIGH {{ background:var(--high); }}
.dot.P2,.dot.MEDIUM {{ background:var(--med); }}
.row {{ padding:10px 14px; border-bottom:1px solid #1a1d22; cursor:pointer; }}
.row:hover,.row.active {{ background:#1a1d24; }}
.row .rid {{ font-family:ui-monospace,Consolas,monospace; font-size:12px; color:var(--accent); }}
.row .msg {{ color:var(--muted); font-size:12px; margin-top:4px; }}
.detail {{ padding:16px; }}
.detail h3 {{ margin:0 0 8px; font-size:16px; }}
.kv {{ display:grid; grid-template-columns:100px 1fr; gap:6px 10px; font-size:13px; margin:12px 0; }}
.kv span {{ color:var(--muted); }}
.ev {{ list-style:none; padding:0; margin:12px 0; }}
.ev li {{ padding:8px 10px; border-left:2px solid var(--accent); background:#12141a; margin-bottom:6px;
  font-family:ui-monospace,Consolas,monospace; font-size:12px; }}
.empty {{ padding:40px 20px; text-align:center; color:var(--muted); }}
.empty.ok {{ color:var(--ok); }}
.footer {{ padding:10px 16px; border-top:1px solid var(--border); color:var(--muted); font-size:12px; }}
@media print {{
  .topbar .actions, .filters, #search, .pane:first-child {{ display:none !important; }}
  .shell {{ display:block; height:auto; }}
  .pane {{ border:none; max-height:none; overflow:visible; }}
  body {{ background:#fff; color:#111; }}
  .row,.detail,.file {{ break-inside:avoid; }}
}}
@media (prefers-reduced-motion:reduce) {{ * {{ transition:none !important; animation:none !important; }} }}
</style>
</head>
<body>
<header class="topbar">
  <div class="brand">ShardGuard</div>
  <div class="meta" id="meta">{n} findings · {tier_s}<br/>{target}<br/>{stamp}</div>
  <div class="actions">
    <button class="btn" type="button" onclick="window.print()">Print / PDF</button>
    <button class="btn" type="button" onclick="dl('json')">JSON</button>
    <button class="btn" type="button" onclick="dl('sarif')">SARIF</button>
    <button class="btn btn-accent" type="button" onclick="dl('zip')">Download ZIP</button>
  </div>
</header>
<div class="shell">
  <aside class="pane" id="files"><h2>Files</h2><div id="fileList"></div></aside>
  <main class="pane">
    <h2>Findings</h2>
    <div class="filters" id="chips"></div>
    <input id="search" type="search" placeholder="Search rule, message, path — press /" autocomplete="off"/>
    <div id="list"></div>
  </main>
  <aside class="pane"><h2>Detail</h2><div class="detail" id="detail"><div class="empty">Select a finding</div></div></aside>
</div>
<footer class="footer">Static analysis cannot prove absence of all bugs (Rice bounds). VM-heavy obfuscators and dynamic-only paths may be OUT_OF_SCOPE. See docs/RICE_BOUNDS.md.</footer>
<script>
const FINDINGS = {data_json};
let sev = "ALL", tier = "ALL", lane = "ALL", fileFilter = "", q = "", idx = 0;
const $ = (id) => document.getElementById(id);

function sevOf(f) {{ return (f.severity || "").toUpperCase(); }}
function tierOf(f) {{ return (f.tier || "").toUpperCase(); }}
function laneOf(f) {{ return (f.lane || "static").toLowerCase(); }}
function pathOf(f) {{
  const p = f.file || "";
  const parts = p.replace(/\\\\/g,"/").split("/");
  return parts[parts.length-1] || p;
}}

function filtered() {{
  const qq = q.trim().toLowerCase();
  return FINDINGS.filter(f => {{
    if (sev !== "ALL" && sevOf(f) !== sev) return false;
    if (tier !== "ALL" && tierOf(f) !== tier) return false;
    if (lane !== "ALL" && laneOf(f) !== lane) return false;
    if (fileFilter && pathOf(f) !== fileFilter) return false;
    if (!qq) return true;
    const blob = [f.rule_id,f.message,f.file,f.lane,f.tier].join(" ").toLowerCase();
    return blob.includes(qq);
  }});
}}

function renderFiles() {{
  const map = {{}};
  FINDINGS.forEach(f => {{
    const k = pathOf(f);
    if (!map[k]) map[k] = {{ n:0, worst:"P3" }};
    map[k].n++;
    const t = tierOf(f);
    if (t === "P0" || (t === "P1" && map[k].worst !== "P0")) map[k].worst = t;
  }});
  const el = $("fileList");
  el.innerHTML = "";
  const all = document.createElement("div");
  all.className = "file" + (fileFilter === "" ? " active" : "");
  all.textContent = "All files (" + FINDINGS.length + ")";
  all.onclick = () => {{ fileFilter = ""; render(); }};
  el.appendChild(all);
  Object.keys(map).sort().forEach(k => {{
    const d = document.createElement("div");
    d.className = "file" + (fileFilter === k ? " active" : "");
    d.innerHTML = '<span class="dot ' + map[k].worst + '"></span>' + k + ' · ' + map[k].n;
    d.onclick = () => {{ fileFilter = k; render(); }};
    el.appendChild(d);
  }});
}}

function renderChips() {{
  const host = $("chips");
  host.innerHTML = "";
  function add(group, values, cur, set) {{
    values.forEach(v => {{
      const b = document.createElement("button");
      b.type = "button";
      b.className = "chip" + (cur === v ? " on" : "");
      b.textContent = v;
      b.onclick = () => {{ set(v); render(); }};
      host.appendChild(b);
    }});
  }}
  add("sev", ["ALL","CRITICAL","HIGH","MEDIUM","LOW"], sev, v => sev = v);
  add("tier", ["ALL","P0","P1","P2","P3"], tier, v => tier = v);
  const lanes = ["ALL", ...new Set(FINDINGS.map(laneOf))];
  add("lane", lanes, lane, v => lane = v);
}}

function renderList() {{
  const rows = filtered();
  const el = $("list");
  if (!FINDINGS.length) {{
    el.innerHTML = '<div class="empty ok">No findings — scan completed clean for configured rules.</div>';
    $("detail").innerHTML = '<div class="empty ok">Clean</div>';
    return;
  }}
  if (!rows.length) {{
    el.innerHTML = '<div class="empty">No findings match filters.</div>';
    return;
  }}
  if (idx >= rows.length) idx = rows.length - 1;
  if (idx < 0) idx = 0;
  el.innerHTML = "";
  rows.forEach((f, i) => {{
    const d = document.createElement("div");
    d.className = "row" + (i === idx ? " active" : "");
    d.innerHTML = '<div class="rid"><span class="dot ' + tierOf(f) + '"></span>' +
      (f.rule_id || "") + '</div><div class="msg">' + (f.message || "").slice(0,120) + '</div>';
    d.onclick = () => {{ idx = i; renderDetail(rows); renderListHighlight(rows); }};
    el.appendChild(d);
  }});
  renderDetail(rows);
}}

function renderListHighlight(rows) {{
  [...$("list").children].forEach((c, i) => c.classList.toggle("active", i === idx));
  renderDetail(rows);
}}

function renderDetail(rows) {{
  const f = rows[idx];
  if (!f) {{ $("detail").innerHTML = '<div class="empty">Select a finding</div>'; return; }}
  const ev = (f.evidence_path || []).map(e => '<li>' + String(e) + '</li>').join("") || "<li>(none)</li>";
  $("detail").innerHTML =
    '<h3>' + (f.rule_id || "") + '</h3>' +
    '<div class="kv">' +
    '<span>Severity</span><div>' + (f.severity||"") + '</div>' +
    '<span>Tier</span><div>' + (f.tier||"") + '</div>' +
    '<span>Lane</span><div>' + (f.lane||"") + '</div>' +
    '<span>Status</span><div>' + (f.status||"") + '</div>' +
    '<span>Location</span><div>' + (f.file||"") + ':' + (f.line||1) +
    ' <button class="btn" type="button" onclick="navigator.clipboard.writeText(\\'' +
    String(f.file||"").replace(/\\\\/g,'/').replace(/'/g,"\\\\'") + ':' + (f.line||1) + '\\')">Copy</button></div>' +
    '<span>Message</span><div>' + (f.message||"") + '</div></div>' +
    '<div style="color:var(--muted);font-size:12px;margin-top:8px">Evidence path</div><ol class="ev">' + ev + '</ol>';
}}

function render() {{
  renderFiles();
  renderChips();
  renderList();
}}

function dl(kind) {{
  if (kind === "json") {{
    const a = document.createElement("a");
    a.href = "SECURITY_REPORT.json"; a.download = "SECURITY_REPORT.json"; a.click(); return;
  }}
  if (kind === "sarif") {{
    const a = document.createElement("a");
    a.href = "findings.sarif"; a.download = "findings.sarif"; a.click(); return;
  }}
  if (kind === "zip") {{
    const a = document.createElement("a");
    a.href = "shardguard-report.zip"; a.download = "shardguard-report.zip"; a.click();
  }}
}}

$("search").addEventListener("input", e => {{ q = e.target.value; idx = 0; renderList(); }});
document.addEventListener("keydown", e => {{
  if (e.key === "/" && document.activeElement !== $("search")) {{ e.preventDefault(); $("search").focus(); }}
  if (e.key === "Escape") {{ $("search").blur(); q = ""; $("search").value = ""; render(); }}
  if (e.key === "j" || e.key === "k") {{
    if (document.activeElement === $("search")) return;
    const rows = filtered();
    if (e.key === "j") idx = Math.min(idx + 1, rows.length - 1);
    else idx = Math.max(idx - 1, 0);
    renderList();
  }}
}});
render();
</script>
</body>
</html>
"""
