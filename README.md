# external-posture

Passive external security posture of a domain, built for pre-sales conversations: email authentication (SPF, DMARC, MTA-STS), DNS hygiene (CAA, DNSSEC), HTTP security headers and cookies, TLS and `security.txt`. Every finding carries a fix and a mapping to NIS2 Article 21(2) and to ENS measures. Reports in English and Spanish. Zero runtime dependencies.

**Live demo:** https://jvch0512.github.io/external-posture/

## What "passive" means here

The scanner reads public information only: a handful of DNS lookups, one GET of the home page (plus one plain-HTTP request to see the redirect), one TLS handshake and one fetch of `/.well-known/security.txt`. No crawling, no port scan, no payloads. Still, **only assess domains you own or have the owner's permission to assess.**

## Use

```
npm install && npm run build
node dist/src/cli.js scan example.com --lang es --save snapshot.json
node dist/src/cli.js analyze examples/weak-fintech.json
node dist/src/cli.js analyze examples/strong-fintech.json --fail-under 90   # CI gate, exit 1 below the score
npm start        # browser UI on http://127.0.0.1:8787
```

Collection and analysis are separate on purpose. A scan produces a `snapshot.json`, and analysis only reads that file. That makes reports reproducible, testable offline and safe to re-run in a meeting without touching the network again. The committed samples in `docs/` are built from fictional `.test` domains, and CI fails if they drift.

## Checks

| Area | Checks |
|---|---|
| Email | SPF missing, duplicated, `+all`, `?all`, softfail, more than 10 lookup terms; DMARC missing, `p=none`, `quarantine`, `pct`, no `rua`; MTA-STS |
| DNS | CAA, DNSSEC validation (resolver AD flag) |
| Web | HTTP to HTTPS redirect, HSTS (presence and max-age), CSP (presence and unsafe sources), nosniff, framing protection, Referrer-Policy, version disclosure, cookie flags |
| TLS | Obsolete protocol, hostname match, expiry |
| Disclosure | `security.txt` presence, Contact, Expires (RFC 9116) |

Severity weights give a 0 to 100 score and an A to F grade. The score is a conversation starter, not an audit result.

## Limits

- DKIM is not checked because the selector is unknown from outside.
- SPF includes are not expanded, so the lookup count is a lower bound.
- In the browser the DNS part runs through Cloudflare DNS over HTTPS (Cloudflare sees the name you type) and headers must be pasted, because browsers cannot read cross-site response headers. The CLI does everything itself.
- NIS2 letters and ENS measure codes (`mp.s.1`, `mp.s.2`, `mp.com.2`, `mp.com.3`, `op.exp.4`) are indicative mappings. Check them against the current texts before quoting them to a client.
- The network collectors are tested with mocks and fixtures, not against live hosts in CI.

MIT licence.
