import { Lang, Result } from "./analyze.js";

const cell = (s: string): string => s.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
const T = {
  en: { h: "External posture", score: "Score", find: "Findings", pass: "Passed", nc: "Not checked", sev: "Severity", title: "Finding", fix: "Fix", nis2: "NIS2 Art. 21(2)", ens: "ENS", none: "No findings.", note: "Passive checks of public information only. Mappings are indicative." },
  es: { h: "Postura externa", score: "Puntuación", find: "Hallazgos", pass: "Correcto", nc: "No comprobado", sev: "Gravedad", title: "Hallazgo", fix: "Corrección", nis2: "NIS2 art. 21.2", ens: "ENS", none: "Sin hallazgos.", note: "Solo comprobaciones pasivas de información pública. Las correspondencias son orientativas." },
};

export function markdown(r: Result, lang: Lang = "en"): string {
  const t = T[lang];
  const L = [`# ${t.h}: ${r.domain}`, "", `${t.score}: **${r.score}/100 (${r.grade})**`, ""];
  L.push(`## ${t.find}`, "");
  if (r.findings.length === 0) L.push(t.none, "");
  else {
    L.push(`| ${t.sev} | ${t.title} | ${t.fix} | ${t.nis2} | ${t.ens} |`, "|---|---|---|---|---|");
    for (const f of r.findings) L.push(`| ${f.severity} | ${cell(f.title[lang])} | ${cell(f.fix[lang])} | ${f.nis2.map((x) => `(${x})`).join(" ")} | ${f.ens.join(", ")} |`);
    L.push("");
  }
  if (r.passed.length) { L.push(`## ${t.pass}`, ""); for (const p of r.passed) L.push(`- ${p}`); L.push(""); }
  if (r.notChecked.length) { L.push(`## ${t.nc}`, "", r.notChecked.join(", "), ""); }
  L.push(`_${t.note}_`, "");
  return L.join("\n");
}
