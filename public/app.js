import { analyze } from "/lib/analyze.js";
import { collectDns } from "/lib/doh.js";
import { markdown } from "/lib/report.js";
import { cleanDomain, parseHeaderBlock, parseSnapshot } from "/lib/snapshot.js";

const $ = (id) => document.getElementById(id);
function el(tag, text, cls) { const e = document.createElement(tag); if (text !== undefined) e.textContent = text; if (cls) e.className = cls; return e; }
function table(headers, rows, classes = []) {
  const t = document.createElement("table");
  const h = document.createElement("tr");
  headers.forEach((x) => h.append(el("th", x)));
  t.append(h);
  rows.forEach((r) => { const tr = document.createElement("tr"); r.forEach((c, i) => tr.append(el("td", String(c), classes[i] ? classes[i](c) : undefined))); t.append(tr); });
  return t;
}
function cards(items) {
  const box = el("div", undefined, "cards");
  for (const [label, value, cls] of items) { const c = el("div", undefined, `card ${cls ?? ""}`); c.append(el("b", String(value)), el("span", label)); box.append(c); }
  return box;
}
function panel(title, ...kids) { const p = el("div", undefined, "panel"); p.append(el("h2", title), ...kids); return p; }
function copyButton(getMd) {
  const b = el("button", "Copy markdown");
  b.type = "button";
  b.addEventListener("click", async () => { try { await navigator.clipboard.writeText(getMd()); b.textContent = "Copied"; setTimeout(() => { b.textContent = "Copy markdown"; }, 1500); } catch { /* clipboard blocked */ } });
  return b;
}
function downloadButton(getMd, name) {
  const b = el("button", "Download .md");
  b.type = "button";
  b.addEventListener("click", () => { const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([getMd()], { type: "text/markdown" })); a.download = name; a.click(); URL.revokeObjectURL(a.href); });
  return b;
}
async function sample(name) { return (await fetch(`/examples/${name}`)).text(); }
function showError(box, e) { box.replaceChildren(el("p", String(e.message ?? e), "err")); }
function setupTabs() {
  document.querySelectorAll("#tabs button").forEach((b) => b.addEventListener("click", () => {
    document.querySelectorAll("#tabs button").forEach((x) => x.classList.toggle("on", x === b));
    document.querySelectorAll(".tab").forEach((s) => { s.hidden = s.id !== `p-${b.dataset.tab}`; });
  }));
}
const cls = (map) => (v) => map[v] ?? "";


const lang = () => $("lang").value;
const SEV = { high: "s-high", medium: "s-medium", low: "s-low", info: "" };

function run() {
  const out = $("out");
  out.replaceChildren();
  const text = $("snap").value.trim();
  if (!text) return;
  try {
    const snap = parseSnapshot(text);
    const hb = $("headers").value.trim();
    if (hb) {
      const p = parseHeaderBlock(hb);
      snap.http = { url: `https://${snap.domain}/`, status: p.status, headers: p.headers, setCookies: p.setCookies, httpRedirectsToHttps: snap.http?.httpRedirectsToHttps ?? null };
    }
    const r = analyze(snap);
    const md = markdown(r, lang());
    out.append(cards([["Score", `${r.score} (${r.grade})`, r.score >= 80 ? "ok" : r.score >= 50 ? "warn" : "bad"], ["Findings", r.findings.length, r.findings.length ? "warn" : "ok"], ["Passed", r.passed.length, "ok"], ["Not checked", r.notChecked.length]]));
    out.append(panel("Findings", r.findings.length
      ? table(["Severity", "Finding", "Fix", "NIS2 21(2)", "ENS"], r.findings.map((f) => [f.severity, f.title[lang()], f.fix[lang()], f.nis2.map((x) => `(${x})`).join(" "), f.ens.join(", ")]), [cls(SEV)])
      : el("p", "No findings."), ...(r.notChecked.length ? [el("p", `Not checked: ${r.notChecked.join(", ")}`, "hint")] : [])));
    if (r.passed.length) out.append(panel("Passed", ...r.passed.map((p) => el("p", p))));
    const row = el("div", undefined, "row");
    row.append(copyButton(() => md), downloadButton(() => md, `posture-${r.domain}.md`));
    out.append(row);
  } catch (e) { showError(out, e); }
}

async function loadSample(name) { $("snap").value = await sample(name); $("headers").value = ""; $("domain").value = JSON.parse($("snap").value).domain; run(); }
$("weak").addEventListener("click", () => loadSample("weak-fintech.json"));
$("strong").addEventListener("click", () => loadSample("strong-fintech.json"));
$("dns-btn").addEventListener("click", async () => {
  const out = $("out");
  try {
    const domain = cleanDomain($("domain").value);
    out.replaceChildren(el("p", `Querying DNS for ${domain}...`, "hint"));
    const dns = await collectDns(domain);
    $("snap").value = JSON.stringify({ domain, collectedAt: new Date().toISOString(), dns, http: null, tls: null, securityTxt: null }, null, 2);
    run();
  } catch (e) { showError(out, e); }
});
$("snap").addEventListener("input", run);
$("headers").addEventListener("input", run);
$("lang").addEventListener("change", run);
