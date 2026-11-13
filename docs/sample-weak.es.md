# Postura externa: weak-fintech.test

Puntuación: **7/100 (F)**

## Hallazgos

| Gravedad | Hallazgo | Corrección | NIS2 art. 21.2 | ENS |
|---|---|---|---|---|
| high | HTTP no redirige a HTTPS | Redirigir todo HTTP a HTTPS con 301. | (h) | mp.com.2 |
| medium | La cookie "PHPSESSID" carece de secure, httponly, samesite | Establecer Secure; HttpOnly; SameSite=Lax (o Strict). | (i) (j) | mp.s.2 |
| medium | Sin Content-Security-Policy | Empezar en modo report-only y después aplicar. | (e) (g) | mp.s.2 |
| medium | DMARC solo en monitorización (p=none) | Revisar informes agregados y aplicar quarantine y reject. | (g) | mp.s.1 |
| medium | Sin HSTS | Enviar Strict-Transport-Security con max-age de al menos 15552000 e includeSubDomains. | (h) | mp.s.2, mp.com.2 |
| medium | SPF supera 10 consultas DNS | Aplanar includes o eliminar emisores en desuso. | (g) | mp.s.1 |
| medium | El certificado caduca en menos de 14 días | Renovar y automatizar la renovación. | (h) (c) | mp.com.3 |
| low | Sin registro CAA | Publicar CAA con solo sus CA. | (h) | mp.com.3 |
| low | DMARC sin dirección de informes agregados | Añadir rua=mailto:... | (f) | mp.s.1 |
| low | DNSSEC no validado | Activar DNSSEC en registrador y proveedor DNS. | (h) | mp.com.3 |
| low | Las páginas pueden enmarcarse desde cualquier sitio | Usar CSP frame-ancestors 'none' o 'self'. | (g) | mp.s.2 |
| low | Sin MTA-STS | Publicar MTA-STS (modo enforce) y TLS-RPT. | (h) (j) | mp.com.2 |
| low | Sin X-Content-Type-Options: nosniff | Enviar X-Content-Type-Options: nosniff. | (g) | mp.s.2 |
| low | Sin security.txt | Publicar /.well-known/security.txt con Contact y Expires. | (e) | op.exp.4 |
| low | SPF con softfail (~all) | Pasar a -all cuando estén todos los emisores. | (g) | mp.s.1 |
| low | El servidor revela versiones de software | Eliminar versiones de Server y X-Powered-By. | (e) (g) | op.exp.4 |
| info | Sin Referrer-Policy | Enviar Referrer-Policy: strict-origin-when-cross-origin. | (g) | mp.s.2 |

## Correcto

- Negotiated TLSv1.2

_Solo comprobaciones pasivas de información pública. Las correspondencias son orientativas._
