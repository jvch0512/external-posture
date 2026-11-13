import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { analyze, spfLookups, tags } from "../src/analyze.js";
import { collectDns, unquoteTxt } from "../src/doh.js";
import { parseSecurityTxt } from "../src/net.js";
import { markdown } from "../src/report.js";
import { Snapshot, SnapshotError, cleanDomain, parseHeaderBlock, parseSnapshot } from "../src/snapshot.js";

const ex = (n: string): string => readFileSync(new URL(`../../examples/${n}`, import.meta.url), "utf8");
const weak = (): Snapshot => parseSnapshot(ex("weak-fintech.json"));
const strong = (): Snapshot => parseSnapshot(ex("strong-fintech.json"));
const ids = (s: Snapshot): string[] => analyze(s).findings.map((f) => f.id);

test("strong example has no findings and grades A", () => {
  const r = analyze(strong());
  assert.deepEqual(r.findings, []);
  assert.equal(r.score, 100);
  assert.equal(r.grade, "A");
  assert.ok(r.passed.length >= 8);
});

test("weak example is flagged across email, web, tls and disclosure", () => {
  const r = analyze(weak());
  const got = r.findings.map((f) => f.id);
  for (const id of ["spf-lookups", "dmarc-monitor", "mtasts-missing", "caa-missing", "dnssec-off", "no-https-redirect", "hsts-missing", "csp-missing", "version-leak", "tls-expiring", "securitytxt-missing", "cookie-PHPSESSID"]) assert.ok(got.includes(id), id);
  assert.ok(!got.includes("cookie-lang"));
  assert.equal(r.grade, "F");
  assert.equal(r.findings[0]!.severity, "high");
});

test("SPF edge cases", () => {
  const s = strong();
  s.dns!.txt = ["v=spf1 +all"];
  assert.ok(ids(s).includes("spf-open"));
  s.dns!.txt = ["v=spf1 include:a.test ?all"];
  assert.ok(ids(s).includes("spf-neutral"));
  s.dns!.txt = ["v=spf1 include:a.test", "v=spf1 -all"];
  assert.ok(ids(s).includes("spf-multiple"));
  s.dns!.txt = [];
  const f = analyze(s).findings.find((x) => x.id === "spf-missing")!;
  assert.equal(f.severity, "high");
  s.dns!.mx = [];
  assert.equal(analyze(s).findings.find((x) => x.id === "spf-missing")!.severity, "low");
});

test("spfLookups counts lookup terms only", () => {
  assert.equal(spfLookups("v=spf1 include:a.test mx a ip4:1.2.3.4 -all"), 3);
  assert.equal(spfLookups("v=spf1 ip4:1.2.3.4 -all"), 0);
  assert.equal(spfLookups("v=spf1 redirect=_spf.a.test"), 1);
});

test("DMARC variants", () => {
  const s = strong();
  s.dns!.dmarc = ["v=DMARC1; p=quarantine; pct=50"];
  const got = ids(s);
  assert.ok(got.includes("dmarc-quarantine") && got.includes("dmarc-pct") && got.includes("dmarc-norua"));
  s.dns!.dmarc = [];
  assert.ok(ids(s).includes("dmarc-missing"));
  assert.deepEqual(tags("v=DMARC1; p=reject; rua=mailto:a@b.test"), { v: "DMARC1", p: "reject", rua: "mailto:a@b.test" });
});

test("TLS and HSTS edge cases", () => {
  const s = strong();
  s.tls = { protocol: "TLSv1.1", daysToExpiry: -3, issuer: "x", hostnameMatches: false };
  const got = ids(s);
  assert.ok(got.includes("tls-old") && got.includes("tls-expired") && got.includes("tls-name"));
  s.http!.headers["strict-transport-security"] = "max-age=300";
  assert.ok(ids(s).includes("hsts-short"));
});

test("CSP with unsafe-inline is a low finding, missing frame protection is caught", () => {
  const s = strong();
  s.http!.headers["content-security-policy"] = "default-src 'self' 'unsafe-inline'";
  assert.ok(ids(s).includes("csp-unsafe"));
  assert.ok(ids(s).includes("framing-open"));
});

test("security.txt checks use the collection time", () => {
  const s = strong();
  s.securityTxt = { found: true, contact: ["mailto:a@b.test"], expires: "2026-01-01T00:00:00Z" };
  assert.ok(ids(s).includes("securitytxt-expired"));
  s.securityTxt = { found: true, contact: [], expires: "2027-01-01T00:00:00Z" };
  assert.ok(ids(s).includes("securitytxt-nocontact"));
});

test("missing sections are reported as not checked, not as failures", () => {
  const s: Snapshot = { domain: "a-b.test", collectedAt: "", dns: null, http: null, tls: null, securityTxt: null };
  const r = analyze(s);
  assert.equal(r.findings.length, 0);
  assert.deepEqual(r.notChecked, ["DNS", "HTTP headers", "TLS", "security.txt"]);
});

test("every finding maps to NIS2 Art. 21(2) and ENS", () => {
  for (const f of analyze(weak()).findings) {
    assert.ok(f.nis2.length > 0 && f.ens.length > 0, f.id);
    assert.ok(f.nis2.every((x) => /^[a-j]$/.test(x)), f.id);
  }
});

test("reports render in English and Spanish", () => {
  const r = analyze(weak());
  assert.match(markdown(r, "en"), /DMARC is monitor-only/);
  const es = markdown(r, "es");
  assert.match(es, /Postura externa/);
  assert.match(es, /DMARC solo en monitorización/);
  assert.match(es, /NIS2 art\. 21\.2/);
});

test("cleanDomain accepts URLs and rejects junk", () => {
  assert.equal(cleanDomain("HTTPS://Sub.Example.com/path?x=1"), "sub.example.com");
  assert.equal(cleanDomain("example.com."), "example.com");
  for (const bad of ["", "localhost", "a b.com", "1.2.3.4", "-x.com", "http://"]) assert.throws(() => cleanDomain(bad), SnapshotError, bad);
});

test("snapshot validation", () => {
  assert.throws(() => parseSnapshot("x"), SnapshotError);
  assert.throws(() => parseSnapshot("[]"), SnapshotError);
  assert.throws(() => parseSnapshot('{"domain":"a.test","dns":{"mx":"nope"}}'), /list of strings/);
});

test("header block parsing handles status, repeated and cookie lines", () => {
  const p = parseHeaderBlock(ex("headers.txt"));
  assert.equal(p.status, 200);
  assert.equal(p.headers["server"], "nginx/1.18.0");
  assert.equal(p.setCookies.length, 2);
  assert.equal(p.headers["set-cookie"], undefined);
});

test("DoH: unquoting joins chunks and collectDns reads answers and the AD flag", () => {
  assert.equal(unquoteTxt('"v=spf1 include:a.test " "-all"'), "v=spf1 include:a.test -all");
  const answers: Record<string, unknown> = {
    "example.test|NS": { Status: 0, AD: true, Answer: [{ name: "example.test.", type: 2, data: "NS2.Host.test." }, { name: "example.test.", type: 2, data: "ns1.host.test." }] },
    "example.test|MX": { Status: 0, Answer: [{ name: "example.test.", type: 15, data: "10 mx.host.test." }] },
    "example.test|TXT": { Status: 0, AD: true, Answer: [{ name: "example.test.", type: 16, data: '"v=spf1 -all"' }] },
    "_dmarc.example.test|TXT": { Status: 0, Answer: [{ name: "_dmarc.example.test.", type: 16, data: '"v=DMARC1; p=reject"' }] },
  };
  const f = async (url: string) => {
    const u = new URL(url);
    const key = `${u.searchParams.get("name")}|${u.searchParams.get("type")}`;
    return { ok: true, json: async () => answers[key] ?? { Status: 0 } };
  };
  return collectDns("example.test", f).then((d) => {
    assert.deepEqual(d.ns, ["ns1.host.test", "ns2.host.test"]);
    assert.deepEqual(d.txt, ["v=spf1 -all"]);
    assert.deepEqual(d.dmarc, ["v=DMARC1; p=reject"]);
    assert.equal(d.dnssec, true);
    assert.deepEqual(d.caa, []);
  });
});

test("DoH failures degrade to empty answers instead of throwing", async () => {
  const d = await collectDns("example.test", async () => ({ ok: false, json: async () => ({}) }));
  assert.deepEqual(d.txt, []);
  assert.equal(d.dnssec, null);
});

test("security.txt parsing", () => {
  const p = parseSecurityTxt("# comment\nContact: mailto:sec@example.test\nContact: https://example.test/report\nExpires: 2027-01-01T00:00:00Z\n");
  assert.equal(p.found, true);
  assert.equal(p.contact.length, 2);
  assert.equal(p.expires, "2027-01-01T00:00:00Z");
  assert.equal(parseSecurityTxt("nothing here").found, false);
});
