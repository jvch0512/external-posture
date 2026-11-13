#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { Lang, analyze } from "./analyze.js";
import { collectDns } from "./doh.js";
import { collectHttp, collectSecurityTxt, collectTls } from "./net.js";
import { markdown } from "./report.js";
import { Snapshot, SnapshotError, cleanDomain, parseSnapshot } from "./snapshot.js";

const USAGE = `external-posture  (passive checks of public information only)

  external-posture scan <domain> [--lang en|es] [--save snapshot.json] [--fail-under N]
  external-posture analyze <snapshot.json> [--lang en|es] [--fail-under N]

Only assess domains you own or have the owner's permission to assess.
Exit codes: 0 ok, 1 score below --fail-under, 2 bad input.`;

const opt = (a: string[], n: string): string | undefined => { const i = a.indexOf(n); return i >= 0 ? a[i + 1] : undefined; };

async function main(argv: string[]): Promise<number> {
  const [cmd, target, ...rest] = argv;
  const all = [target ?? "", ...rest];
  const lang = (opt(all, "--lang") ?? "en") as Lang;
  if (lang !== "en" && lang !== "es") { console.error("error: --lang must be en or es"); return 2; }
  try {
    let snap: Snapshot;
    if (cmd === "scan" && target) {
      const domain = cleanDomain(target);
      const [dns, http, tls, securityTxt] = await Promise.all([collectDns(domain).catch(() => null), collectHttp(domain), collectTls(domain), collectSecurityTxt(domain)]);
      snap = { domain, collectedAt: new Date().toISOString(), dns, http, tls, securityTxt };
      const save = opt(rest, "--save");
      if (save) writeFileSync(save, JSON.stringify(snap, null, 2));
    } else if (cmd === "analyze" && target) snap = parseSnapshot(readFileSync(target, "utf8"));
    else { console.error(USAGE); return 2; }
    const r = analyze(snap);
    process.stdout.write(markdown(r, lang));
    const min = opt(rest, "--fail-under");
    return min !== undefined && r.score < Number(min) ? 1 : 0;
  } catch (e) {
    if (e instanceof SnapshotError) { console.error(`error: ${e.message}`); return 2; }
    if ((e as NodeJS.ErrnoException).code === "ENOENT") { console.error(`error: cannot read ${(e as NodeJS.ErrnoException).path}`); return 2; }
    throw e;
  }
}

main(process.argv.slice(2)).then((c) => { process.exitCode = c; });
