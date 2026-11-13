# External posture: weak-fintech.test

Score: **7/100 (F)**

## Findings

| Severity | Finding | Fix | NIS2 Art. 21(2) | ENS |
|---|---|---|---|---|
| high | HTTP does not redirect to HTTPS | Redirect all HTTP to HTTPS with a 301. | (h) | mp.com.2 |
| medium | Cookie "PHPSESSID" lacks secure, httponly, samesite | Set Secure; HttpOnly; SameSite=Lax (or Strict). | (i) (j) | mp.s.2 |
| medium | No Content-Security-Policy | Start with a report-only policy, then enforce. | (e) (g) | mp.s.2 |
| medium | DMARC is monitor-only (p=none) | Review the aggregate reports, then enforce with quarantine and reject. | (g) | mp.s.1 |
| medium | No HSTS | Send Strict-Transport-Security with max-age of at least 15552000 and includeSubDomains. | (h) | mp.s.2, mp.com.2 |
| medium | SPF exceeds 10 DNS lookups | Flatten includes or remove unused senders. | (g) | mp.s.1 |
| medium | Certificate expires within 14 days | Renew and automate renewal. | (h) (c) | mp.com.3 |
| low | No CAA record | Publish CAA listing only your CAs. | (h) | mp.com.3 |
| low | DMARC has no aggregate reporting address | Add rua=mailto:... | (f) | mp.s.1 |
| low | DNSSEC not validated | Enable DNSSEC at the registrar and DNS host. | (h) | mp.com.3 |
| low | Pages can be framed by any site | Use CSP frame-ancestors 'none' or 'self'. | (g) | mp.s.2 |
| low | No MTA-STS | Publish MTA-STS (enforce mode) and TLS-RPT. | (h) (j) | mp.com.2 |
| low | No X-Content-Type-Options: nosniff | Send X-Content-Type-Options: nosniff. | (g) | mp.s.2 |
| low | No security.txt | Publish /.well-known/security.txt with Contact and Expires. | (e) | op.exp.4 |
| low | SPF uses softfail (~all) | Move to -all once all senders are listed. | (g) | mp.s.1 |
| low | Server discloses software versions | Remove version details from Server and X-Powered-By. | (e) (g) | op.exp.4 |
| info | No Referrer-Policy | Send Referrer-Policy: strict-origin-when-cross-origin. | (g) | mp.s.2 |

## Passed

- Negotiated TLSv1.2

_Passive checks of public information only. Mappings are indicative._
