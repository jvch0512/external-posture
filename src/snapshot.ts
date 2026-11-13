/** What a passive collection of a domain looks like. Collectors fill it, analysis only reads it, so everything is testable offline. */

export interface DnsData {
  ns: string[];
  mx: string[];
  txt: string[];
  dmarc: string[];
  mtaSts: string[];
  tlsRpt: string[];
  caa: string[];
  /** true when the resolver validated the answer (AD flag), null when unknown */
  dnssec: boolean | null;
}

export interface HttpData {
  url: string;
  status: number;
  headers: Record<string, string>;
  setCookies: string[];
  httpRedirectsToHttps: boolean | null;
}

export interface TlsData {
  protocol: string;
  daysToExpiry: number;
  issuer: string;
  hostnameMatches: boolean;
}

export interface SecurityTxt {
  found: boolean;
  contact: string[];
  expires: string;
}

export interface Snapshot {
  domain: string;
  collectedAt: string;
  dns: DnsData | null;
  http: HttpData | null;
  tls: TlsData | null;
  securityTxt: SecurityTxt | null;
}

export class SnapshotError extends Error {}

const DOMAIN = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

export function cleanDomain(input: string): string {
  const d = input.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/\.$/, "");
  if (!DOMAIN.test(d)) throw new SnapshotError(`not a valid domain name: ${input.slice(0, 80)}`);
  return d;
}

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const strs = (v: unknown, f: string): string[] => {
  if (v === undefined) return [];
  if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) throw new SnapshotError(`${f} must be a list of strings`);
  return v as string[];
};

export function parseSnapshot(text: string): Snapshot {
  let raw: unknown;
  try { raw = JSON.parse(text); } catch { throw new SnapshotError("snapshot is not valid JSON"); }
  if (!isObj(raw)) throw new SnapshotError("snapshot must be an object");
  const domain = cleanDomain(String(raw["domain"] ?? ""));
  const d = raw["dns"];
  const dns: DnsData | null = isObj(d) ? {
    ns: strs(d["ns"], "dns.ns"), mx: strs(d["mx"], "dns.mx"), txt: strs(d["txt"], "dns.txt"), dmarc: strs(d["dmarc"], "dns.dmarc"),
    mtaSts: strs(d["mtaSts"], "dns.mtaSts"), tlsRpt: strs(d["tlsRpt"], "dns.tlsRpt"), caa: strs(d["caa"], "dns.caa"),
    dnssec: typeof d["dnssec"] === "boolean" ? d["dnssec"] : null,
  } : null;
  const h = raw["http"];
  let http: HttpData | null = null;
  if (isObj(h)) {
    const headers: Record<string, string> = {};
    if (isObj(h["headers"])) for (const [k, v] of Object.entries(h["headers"])) if (typeof v === "string") headers[k.toLowerCase()] = v;
    http = { url: String(h["url"] ?? `https://${domain}/`), status: Number(h["status"] ?? 0), headers, setCookies: strs(h["setCookies"], "http.setCookies"), httpRedirectsToHttps: typeof h["httpRedirectsToHttps"] === "boolean" ? h["httpRedirectsToHttps"] : null };
  }
  const t = raw["tls"];
  const tls: TlsData | null = isObj(t) ? { protocol: String(t["protocol"] ?? ""), daysToExpiry: Number(t["daysToExpiry"] ?? 0), issuer: String(t["issuer"] ?? ""), hostnameMatches: t["hostnameMatches"] !== false } : null;
  const s = raw["securityTxt"];
  const securityTxt: SecurityTxt | null = isObj(s) ? { found: s["found"] === true, contact: strs(s["contact"], "securityTxt.contact"), expires: String(s["expires"] ?? "") } : null;
  return { domain, collectedAt: String(raw["collectedAt"] ?? ""), dns, http, tls, securityTxt };
}

/** Parse "Name: value" lines pasted from a browser's network tab or `curl -I`. */
export function parseHeaderBlock(text: string): { headers: Record<string, string>; setCookies: string[]; status: number } {
  const headers: Record<string, string> = {};
  const setCookies: string[] = [];
  let status = 0;
  for (const line of text.split(/\r?\n/)) {
    const st = /^HTTP\/[\d.]+\s+(\d{3})/.exec(line);
    if (st) { status = Number(st[1]); continue; }
    const i = line.indexOf(":");
    if (i <= 0) continue;
    const k = line.slice(0, i).trim().toLowerCase();
    const v = line.slice(i + 1).trim();
    if (!/^[a-z0-9-]+$/.test(k)) continue;
    if (k === "set-cookie") setCookies.push(v);
    else headers[k] = headers[k] ? `${headers[k]}, ${v}` : v;
  }
  return { headers, setCookies, status };
}
