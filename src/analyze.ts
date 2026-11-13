import { Snapshot } from "./snapshot.js";

export type Lang = "en" | "es";
export type Severity = "high" | "medium" | "low" | "info";
interface L { en: string; es: string }
const l = (en: string, es: string): L => ({ en, es });

export interface Finding {
  id: string;
  area: "email" | "dns" | "web" | "tls" | "disclosure";
  severity: Severity;
  title: L;
  detail: string;
  fix: L;
  /** NIS2 Article 21(2) letters */
  nis2: string[];
  ens: string[];
}

export interface Result { domain: string; findings: Finding[]; score: number; grade: string; passed: string[]; notChecked: string[] }

const W: Record<Severity, number> = { high: 18, medium: 8, low: 3, info: 0 };

export function spfOf(txt: string[]): string[] { return txt.filter((t) => /^v=spf1(\s|$)/i.test(t.trim())); }

/** DNS lookups the record itself triggers (includes are not expanded). */
export function spfLookups(rec: string): number {
  return rec.split(/\s+/).filter((t) => /^(include:|a(:|\/|$)|mx(:|\/|$)|ptr(:|$)|exists:|redirect=)/i.test(t.replace(/^[+\-~?]/, ""))).length;
}

export function tags(rec: string): Record<string, string> {
  const o: Record<string, string> = {};
  for (const part of rec.split(";")) { const i = part.indexOf("="); if (i > 0) o[part.slice(0, i).trim().toLowerCase()] = part.slice(i + 1).trim(); }
  return o;
}

export function analyze(s: Snapshot): Result {
  const f: Finding[] = [];
  const passed: string[] = [];
  const notChecked: string[] = [];
  const add = (x: Finding) => f.push(x);

  // ---- email authentication
  if (s.dns) {
    const hasMx = s.dns.mx.length > 0;
    const spf = spfOf(s.dns.txt);
    if (spf.length === 0) {
      add({ id: "spf-missing", area: "email", severity: hasMx ? "high" : "low", title: l("No SPF record", "Sin registro SPF"), detail: hasMx ? "The domain receives mail but publishes no SPF policy, so anyone can claim to send as it." : "No mail exchangers; publish `v=spf1 -all` to forbid spoofed mail.", fix: l("Publish an SPF record that lists your senders and ends with -all.", "Publicar un registro SPF con sus emisores y terminar en -all."), nis2: ["g", "j"], ens: ["mp.s.1"] });
    } else if (spf.length > 1) {
      add({ id: "spf-multiple", area: "email", severity: "high", title: l("More than one SPF record", "Más de un registro SPF"), detail: "Receivers treat multiple SPF records as a permanent error, which disables SPF.", fix: l("Merge into a single SPF record.", "Unificar en un único registro SPF."), nis2: ["g"], ens: ["mp.s.1"] });
    } else {
      const r = spf[0]!;
      const all = /(^|\s)([+\-~?]?)all(\s|$)/i.exec(r)?.[2] ?? "";
      if (/(^|\s)\+all(\s|$)/i.test(r) || (/(^|\s)all(\s|$)/i.test(r) && all === "")) add({ id: "spf-open", area: "email", severity: "high", title: l("SPF allows any sender", "SPF permite cualquier emisor"), detail: `Record ends with an open "all": ${r}`, fix: l("Replace +all with -all (or ~all while you inventory senders).", "Sustituir +all por -all (o ~all mientras inventaría emisores)."), nis2: ["g"], ens: ["mp.s.1"] });
      else if (all === "?") add({ id: "spf-neutral", area: "email", severity: "medium", title: l("SPF is neutral (?all)", "SPF neutro (?all)"), detail: "?all asserts nothing about unlisted senders.", fix: l("Move to ~all, then -all.", "Pasar a ~all y después a -all."), nis2: ["g"], ens: ["mp.s.1"] });
      else if (all === "~") add({ id: "spf-softfail", area: "email", severity: "low", title: l("SPF uses softfail (~all)", "SPF con softfail (~all)"), detail: "Softfail is acceptable while enforcement relies on DMARC.", fix: l("Move to -all once all senders are listed.", "Pasar a -all cuando estén todos los emisores."), nis2: ["g"], ens: ["mp.s.1"] });
      else if (all === "-") passed.push("SPF ends with -all");
      else add({ id: "spf-noall", area: "email", severity: "medium", title: l("SPF has no 'all' mechanism", "SPF sin mecanismo 'all'"), detail: `Record: ${r}`, fix: l("End the record with -all.", "Terminar el registro con -all."), nis2: ["g"], ens: ["mp.s.1"] });
      const n = spfLookups(r);
      if (n > 10) add({ id: "spf-lookups", area: "email", severity: "medium", title: l("SPF exceeds 10 DNS lookups", "SPF supera 10 consultas DNS"), detail: `${n} lookup terms in the top-level record alone (RFC 7208 limit is 10), so receivers may return permerror.`, fix: l("Flatten includes or remove unused senders.", "Aplanar includes o eliminar emisores en desuso."), nis2: ["g"], ens: ["mp.s.1"] });
    }
    const dm = s.dns.dmarc.filter((t) => /^v=DMARC1/i.test(t.trim()));
    if (dm.length === 0) {
      add({ id: "dmarc-missing", area: "email", severity: hasMx ? "high" : "medium", title: l("No DMARC record", "Sin registro DMARC"), detail: "Without DMARC, spoofed mail from your domain is not rejected and you get no reports.", fix: l("Publish _dmarc with p=none and rua= first, then move to quarantine and reject.", "Publicar _dmarc con p=none y rua= primero, y subir a quarantine y reject."), nis2: ["g", "j"], ens: ["mp.s.1"] });
    } else {
      const t = tags(dm[0]!);
      const p = (t["p"] ?? "").toLowerCase();
      if (p === "reject") passed.push("DMARC policy is reject");
      else if (p === "quarantine") add({ id: "dmarc-quarantine", area: "email", severity: "low", title: l("DMARC at quarantine", "DMARC en quarantine"), detail: "Quarantine is a good step; reject gives the strongest protection.", fix: l("Move to p=reject after reviewing reports.", "Pasar a p=reject tras revisar los informes."), nis2: ["g"], ens: ["mp.s.1"] });
      else add({ id: "dmarc-monitor", area: "email", severity: "medium", title: l("DMARC is monitor-only (p=none)", "DMARC solo en monitorización (p=none)"), detail: "Spoofed mail is still delivered.", fix: l("Review the aggregate reports, then enforce with quarantine and reject.", "Revisar informes agregados y aplicar quarantine y reject."), nis2: ["g"], ens: ["mp.s.1"] });
      if (t["pct"] !== undefined && Number(t["pct"]) < 100 && p !== "none") add({ id: "dmarc-pct", area: "email", severity: "low", title: l("DMARC applies to part of the mail only", "DMARC se aplica solo a parte del correo"), detail: `pct=${t["pct"]}`, fix: l("Raise pct to 100.", "Subir pct a 100."), nis2: ["g"], ens: ["mp.s.1"] });
      if (!t["rua"]) add({ id: "dmarc-norua", area: "email", severity: "low", title: l("DMARC has no aggregate reporting address", "DMARC sin dirección de informes agregados"), detail: "Without rua= you cannot see who sends as your domain.", fix: l("Add rua=mailto:...", "Añadir rua=mailto:..."), nis2: ["f"], ens: ["mp.s.1"] });
    }
    if (hasMx) {
      if (s.dns.mtaSts.some((t) => /^v=STSv1/i.test(t))) passed.push("MTA-STS published"); else add({ id: "mtasts-missing", area: "email", severity: "low", title: l("No MTA-STS", "Sin MTA-STS"), detail: "Mail transport can be downgraded to plaintext by an active attacker.", fix: l("Publish MTA-STS (enforce mode) and TLS-RPT.", "Publicar MTA-STS (modo enforce) y TLS-RPT."), nis2: ["h", "j"], ens: ["mp.com.2"] });
    }
    if (s.dns.caa.length) passed.push("CAA restricts certificate issuance"); else add({ id: "caa-missing", area: "dns", severity: "low", title: l("No CAA record", "Sin registro CAA"), detail: "Any certificate authority may issue certificates for the domain.", fix: l("Publish CAA listing only your CAs.", "Publicar CAA con solo sus CA."), nis2: ["h"], ens: ["mp.com.3"] });
    if (s.dns.dnssec === true) passed.push("DNSSEC validated"); else if (s.dns.dnssec === false) add({ id: "dnssec-off", area: "dns", severity: "low", title: l("DNSSEC not validated", "DNSSEC no validado"), detail: "Answers for this domain are not cryptographically signed.", fix: l("Enable DNSSEC at the registrar and DNS host.", "Activar DNSSEC en registrador y proveedor DNS."), nis2: ["h"], ens: ["mp.com.3"] }); else notChecked.push("DNSSEC");
  } else notChecked.push("DNS");

  // ---- web
  if (s.http) {
    const h = s.http.headers;
    if (s.http.httpRedirectsToHttps === false) add({ id: "no-https-redirect", area: "web", severity: "high", title: l("HTTP does not redirect to HTTPS", "HTTP no redirige a HTTPS"), detail: "Visitors who type the bare domain stay on plaintext.", fix: l("Redirect all HTTP to HTTPS with a 301.", "Redirigir todo HTTP a HTTPS con 301."), nis2: ["h"], ens: ["mp.com.2"] });
    else if (s.http.httpRedirectsToHttps === true) passed.push("HTTP redirects to HTTPS");
    const hsts = h["strict-transport-security"];
    if (!hsts) add({ id: "hsts-missing", area: "web", severity: "medium", title: l("No HSTS", "Sin HSTS"), detail: "Browsers can be downgraded to HTTP on the first visit or after expiry.", fix: l("Send Strict-Transport-Security with max-age of at least 15552000 and includeSubDomains.", "Enviar Strict-Transport-Security con max-age de al menos 15552000 e includeSubDomains."), nis2: ["h"], ens: ["mp.s.2", "mp.com.2"] });
    else {
      const age = Number(/max-age=(\d+)/i.exec(hsts)?.[1] ?? 0);
      if (age < 15552000) add({ id: "hsts-short", area: "web", severity: "low", title: l("HSTS max-age is short", "HSTS con max-age corto"), detail: `max-age=${age}`, fix: l("Use at least 15552000 seconds (180 days).", "Usar al menos 15552000 segundos (180 días)."), nis2: ["h"], ens: ["mp.s.2"] });
      else passed.push("HSTS with a long max-age");
    }
    const csp = h["content-security-policy"];
    if (!csp) add({ id: "csp-missing", area: "web", severity: "medium", title: l("No Content-Security-Policy", "Sin Content-Security-Policy"), detail: "No browser-enforced limit on where scripts and frames load from.", fix: l("Start with a report-only policy, then enforce.", "Empezar en modo report-only y después aplicar."), nis2: ["e", "g"], ens: ["mp.s.2"] });
    else if (/'unsafe-inline'|'unsafe-eval'/.test(csp) && /script-src|default-src/.test(csp)) add({ id: "csp-unsafe", area: "web", severity: "low", title: l("CSP allows unsafe script sources", "CSP permite orígenes de script inseguros"), detail: "unsafe-inline or unsafe-eval weakens the policy.", fix: l("Use nonces or hashes instead.", "Usar nonces o hashes."), nis2: ["e"], ens: ["mp.s.2"] });
    else passed.push("Content-Security-Policy present");
    if ((h["x-content-type-options"] ?? "").toLowerCase() !== "nosniff") add({ id: "nosniff-missing", area: "web", severity: "low", title: l("No X-Content-Type-Options: nosniff", "Sin X-Content-Type-Options: nosniff"), detail: "Browsers may sniff content types.", fix: l("Send X-Content-Type-Options: nosniff.", "Enviar X-Content-Type-Options: nosniff."), nis2: ["g"], ens: ["mp.s.2"] });
    if (!h["x-frame-options"] && !/frame-ancestors/i.test(csp ?? "")) add({ id: "framing-open", area: "web", severity: "low", title: l("Pages can be framed by any site", "Las páginas pueden enmarcarse desde cualquier sitio"), detail: "No X-Frame-Options and no CSP frame-ancestors: clickjacking is possible.", fix: l("Use CSP frame-ancestors 'none' or 'self'.", "Usar CSP frame-ancestors 'none' o 'self'."), nis2: ["g"], ens: ["mp.s.2"] });
    if (!h["referrer-policy"]) add({ id: "referrer-missing", area: "web", severity: "info", title: l("No Referrer-Policy", "Sin Referrer-Policy"), detail: "Browsers apply their own default.", fix: l("Send Referrer-Policy: strict-origin-when-cross-origin.", "Enviar Referrer-Policy: strict-origin-when-cross-origin."), nis2: ["g"], ens: ["mp.s.2"] });
    const srv = `${h["server"] ?? ""} ${h["x-powered-by"] ?? ""}`;
    if (/\d+\.\d+/.test(srv)) add({ id: "version-leak", area: "web", severity: "low", title: l("Server discloses software versions", "El servidor revela versiones de software"), detail: srv.trim(), fix: l("Remove version details from Server and X-Powered-By.", "Eliminar versiones de Server y X-Powered-By."), nis2: ["e", "g"], ens: ["op.exp.4"] });
    for (const c of s.http.setCookies) {
      const name = c.split("=")[0] ?? "cookie";
      const miss = ["secure", "httponly", "samesite"].filter((a) => !new RegExp(`;\\s*${a}(=|;|$)`, "i").test(c));
      if (miss.length) add({ id: `cookie-${name}`, area: "web", severity: "medium", title: l(`Cookie "${name}" lacks ${miss.join(", ")}`, `La cookie "${name}" carece de ${miss.join(", ")}`), detail: "Session cookies should set Secure, HttpOnly and SameSite.", fix: l("Set Secure; HttpOnly; SameSite=Lax (or Strict).", "Establecer Secure; HttpOnly; SameSite=Lax (o Strict)."), nis2: ["i", "j"], ens: ["mp.s.2"] });
    }
  } else notChecked.push("HTTP headers");

  // ---- TLS
  if (s.tls) {
    if (/^TLSv1(\.0|\.1)?$/.test(s.tls.protocol) || /^SSL/i.test(s.tls.protocol)) add({ id: "tls-old", area: "tls", severity: "high", title: l(`Obsolete protocol ${s.tls.protocol}`, `Protocolo obsoleto ${s.tls.protocol}`), detail: "TLS 1.0 and 1.1 are deprecated (RFC 8996).", fix: l("Allow TLS 1.2 and 1.3 only.", "Permitir solo TLS 1.2 y 1.3."), nis2: ["h"], ens: ["mp.com.2"] });
    else passed.push(`Negotiated ${s.tls.protocol}`);
    if (!s.tls.hostnameMatches) add({ id: "tls-name", area: "tls", severity: "high", title: l("Certificate does not match the hostname", "El certificado no coincide con el nombre"), detail: "Browsers will show a warning.", fix: l("Issue a certificate covering the hostname.", "Emitir un certificado que cubra el nombre."), nis2: ["h"], ens: ["mp.com.3"] });
    if (s.tls.daysToExpiry < 0) add({ id: "tls-expired", area: "tls", severity: "high", title: l("Certificate expired", "Certificado caducado"), detail: `${-s.tls.daysToExpiry} days ago`, fix: l("Renew now and automate renewal.", "Renovar ya y automatizar la renovación."), nis2: ["h", "c"], ens: ["mp.com.3"] });
    else if (s.tls.daysToExpiry < 14) add({ id: "tls-expiring", area: "tls", severity: "medium", title: l("Certificate expires within 14 days", "El certificado caduca en menos de 14 días"), detail: `${s.tls.daysToExpiry} days left`, fix: l("Renew and automate renewal.", "Renovar y automatizar la renovación."), nis2: ["h", "c"], ens: ["mp.com.3"] });
    else passed.push(`Certificate valid for ${s.tls.daysToExpiry} more days`);
  } else notChecked.push("TLS");

  // ---- disclosure
  if (s.securityTxt) {
    if (!s.securityTxt.found) add({ id: "securitytxt-missing", area: "disclosure", severity: "low", title: l("No security.txt", "Sin security.txt"), detail: "Researchers have no published way to report a vulnerability (RFC 9116).", fix: l("Publish /.well-known/security.txt with Contact and Expires.", "Publicar /.well-known/security.txt con Contact y Expires."), nis2: ["e"], ens: ["op.exp.4"] });
    else {
      if (!s.securityTxt.contact.length) add({ id: "securitytxt-nocontact", area: "disclosure", severity: "medium", title: l("security.txt has no Contact", "security.txt sin Contact"), detail: "Contact is mandatory in RFC 9116.", fix: l("Add a Contact field.", "Añadir un campo Contact."), nis2: ["e"], ens: ["op.exp.4"] });
      const exp = Date.parse(s.securityTxt.expires);
      if (!Number.isFinite(exp)) add({ id: "securitytxt-noexpires", area: "disclosure", severity: "low", title: l("security.txt has no valid Expires", "security.txt sin Expires válido"), detail: "Expires is mandatory in RFC 9116.", fix: l("Add an Expires date within a year.", "Añadir una fecha Expires dentro de un año."), nis2: ["e"], ens: ["op.exp.4"] });
      else if (exp < Date.parse(s.collectedAt || new Date().toISOString())) add({ id: "securitytxt-expired", area: "disclosure", severity: "low", title: l("security.txt has expired", "security.txt caducado"), detail: s.securityTxt.expires, fix: l("Refresh the Expires date.", "Renovar la fecha Expires."), nis2: ["e"], ens: ["op.exp.4"] });
      else if (s.securityTxt.contact.length) passed.push("security.txt with Contact and a valid Expires");
    }
  } else notChecked.push("security.txt");

  f.sort((a, b) => W[b.severity] - W[a.severity] || a.id.localeCompare(b.id));
  const score = Math.max(0, 100 - f.reduce((n, x) => n + W[x.severity], 0));
  const grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 65 ? "C" : score >= 50 ? "D" : "F";
  return { domain: s.domain, findings: f, score, grade, passed, notChecked };
}
