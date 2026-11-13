/** Node-only collectors: one GET of the home page, one TLS handshake, one security.txt fetch. No crawling, no payloads. */
import https from "node:https";
import http from "node:http";
import tls from "node:tls";
import { HttpData, SecurityTxt, TlsData } from "./snapshot.js";

const TIMEOUT = 8000;

export function getOnce(url: string, plain = false): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }> {
  return new Promise((resolve, reject) => {
    const mod = plain ? http : https;
    const req = mod.get(url, { timeout: TIMEOUT, headers: { "user-agent": "external-posture/1.0 (passive check)" } }, (res) => {
      const chunks: Buffer[] = [];
      let n = 0;
      res.on("data", (c: Buffer) => { n += c.length; if (n < 64 * 1024) chunks.push(c); else res.destroy(); });
      res.on("close", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") }));
      res.on("error", reject);
    });
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", reject);
  });
}

export async function collectHttp(domain: string): Promise<HttpData | null> {
  try {
    const r = await getOnce(`https://${domain}/`);
    let redirects: boolean | null = null;
    try {
      const p = await getOnce(`http://${domain}/`, true);
      redirects = p.status >= 300 && p.status < 400 && /^https:/i.test(String(p.headers["location"] ?? ""));
    } catch { redirects = null; }
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(r.headers)) if (k !== "set-cookie" && v !== undefined) headers[k] = Array.isArray(v) ? v.join(", ") : v;
    return { url: `https://${domain}/`, status: r.status, headers, setCookies: r.headers["set-cookie"] ?? [], httpRedirectsToHttps: redirects };
  } catch { return null; }
}

export function collectTls(domain: string): Promise<TlsData | null> {
  return new Promise((resolve) => {
    const sock = tls.connect({ host: domain, port: 443, servername: domain, timeout: TIMEOUT, rejectUnauthorized: false }, () => {
      const cert = sock.getPeerCertificate();
      const proto = sock.getProtocol() ?? "";
      const left = cert.valid_to ? Math.floor((Date.parse(cert.valid_to) - Date.now()) / 86_400_000) : 0;
      let matches = true;
      try { matches = tls.checkServerIdentity(domain, cert) === undefined; } catch { matches = false; }
      const issuer = cert.issuer ? String(cert.issuer.O ?? cert.issuer.CN ?? "") : "";
      sock.end();
      resolve({ protocol: proto, daysToExpiry: left, issuer, hostnameMatches: matches });
    });
    sock.on("timeout", () => { sock.destroy(); resolve(null); });
    sock.on("error", () => resolve(null));
  });
}

export function parseSecurityTxt(body: string): SecurityTxt {
  const contact: string[] = [];
  let expires = "";
  for (const line of body.split(/\r?\n/)) {
    const m = /^(Contact|Expires):\s*(.+)$/i.exec(line.trim());
    if (!m) continue;
    if (m[1]!.toLowerCase() === "contact") contact.push(m[2]!.trim()); else expires = m[2]!.trim();
  }
  return { found: contact.length > 0 || expires !== "" , contact, expires };
}

export async function collectSecurityTxt(domain: string): Promise<SecurityTxt | null> {
  try {
    const r = await getOnce(`https://${domain}/.well-known/security.txt`);
    if (r.status !== 200 || /^\s*</.test(r.body)) return { found: false, contact: [], expires: "" };
    return parseSecurityTxt(r.body);
  } catch { return null; }
}
