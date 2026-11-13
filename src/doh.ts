/** DNS over HTTPS (JSON API). Uses global fetch, so it runs in Node 20+ and in the browser. */
import { DnsData } from "./snapshot.js";

export const DOH = "https://cloudflare-dns.com/dns-query";
type Fetch = (url: string, init?: { headers?: Record<string, string>; signal?: AbortSignal }) => Promise<{ ok: boolean; json(): Promise<unknown> }>;

interface DohAnswer { name: string; type: number; data: string }
interface DohResponse { Status: number; AD?: boolean; Answer?: DohAnswer[] }

const TYPES: Record<string, number> = { NS: 2, MX: 15, TXT: 16, CAA: 257 };

/** TXT data comes back quoted and possibly split in chunks: join the chunks and drop the quotes. */
export function unquoteTxt(data: string): string {
  const parts = [...data.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => (m[1] ?? "").replace(/\\(.)/g, "$1"));
  return parts.length ? parts.join("") : data;
}

async function query(f: Fetch, name: string, type: string): Promise<{ answers: DohAnswer[]; ad: boolean }> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 8000);
  try {
    const res = await f(`${DOH}?name=${encodeURIComponent(name)}&type=${type}&do=1`, { headers: { accept: "application/dns-json" }, signal: ctl.signal });
    if (!res.ok) return { answers: [], ad: false };
    const j = (await res.json()) as DohResponse;
    const want = TYPES[type];
    return { answers: (j.Answer ?? []).filter((a) => a.type === want), ad: j.AD === true };
  } finally { clearTimeout(timer); }
}

export async function collectDns(domain: string, f: Fetch = fetch as unknown as Fetch): Promise<DnsData> {
  const [ns, mx, txt, dmarc, mtaSts, tlsRpt, caa] = await Promise.all([
    query(f, domain, "NS"), query(f, domain, "MX"), query(f, domain, "TXT"), query(f, `_dmarc.${domain}`, "TXT"),
    query(f, `_mta-sts.${domain}`, "TXT"), query(f, `_smtp._tls.${domain}`, "TXT"), query(f, domain, "CAA"),
  ]);
  const t = (r: { answers: DohAnswer[] }) => r.answers.map((a) => unquoteTxt(a.data));
  return {
    ns: ns.answers.map((a) => a.data.replace(/\.$/, "").toLowerCase()).sort(),
    mx: mx.answers.map((a) => a.data.replace(/\.$/, "").toLowerCase()).sort(),
    txt: t(txt), dmarc: t(dmarc), mtaSts: t(mtaSts), tlsRpt: t(tlsRpt),
    caa: caa.answers.map((a) => a.data),
    dnssec: ns.answers.length || txt.answers.length ? txt.ad || ns.ad : null,
  };
}
