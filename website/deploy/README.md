# Nodus website deployment

Published on 14 September 2026 after explicit user approval. The user supplied
Cloudflare DNS records; the assistant installed the three sites and certificates
on the existing CPUNK Nginx host.

| Site | Document root | Certificate name |
| --- | --- | --- |
| https://nodusnetwork.io/ | `/var/www/nodusnetwork.io/public` | `nodusnetwork.io` (also www) |
| https://wiki.nodusnetwork.io/ | `/var/www/wiki.nodusnetwork.io/public` | `wiki.nodusnetwork.io` |
| https://scan.nodusnetwork.io/ | `/var/www/scan.nodusnetwork.io/public` | `scan.nodusnetwork.io` |

Each has `/etc/nginx/sites-available/<domain>` and a matching enabled symlink.
The installed configurations are nginx-https.conf, wiki-https.conf and
scan-https.conf in this directory. HTTP redirects to HTTPS; www redirects to the
bare main domain, preserving paths and queries. Production needs no Node process.

## Host and API

The host uses Nginx 1.26.3 and Certbot 4.0.0. Apache and Caddy are absent.
Addresses and credentials stay in local operational records, outside git.
Existing CPUNK vhost files were backed up; their SHA-256 checksums remained
identical after installation, and CPUNK HTTPS continued returning 200.

Scan proxies read-only requests under `/api/` to the existing indexer at
`127.0.0.1:8390`, with its own `nodus_scan_api` rate-limit zone. Its process,
database and native chain services were not changed. API responses use
`Cache-Control: no-store`. The observed indexed height was 286; API availability
is not evidence that the development chain is currently producing blocks.
The current indexer accepts GET; its HEAD response is 405. Verify API health
with GET rather than `curl -I`. Nginx rejects write methods before proxying.

Static responses use `public, max-age=0, must-revalidate, no-transform`. This
prevents Cloudflare's automatic analytics injection, which initially conflicted
with the site's local-only CSP. The behavior is documented in
[Cloudflare Web Analytics setup](https://developers.cloudflare.com/web-analytics/get-started/).
Cloudflare also adds managed content to robots.txt; the original crawler and
sitemap directives were verified to remain in each response.

## Certificates and renewal

Let's Encrypt certificates were issued with webroot mode using the existing
production ACME account. All three currently expire on 13 December 2026.
`certbot.timer` is active and enabled. Each certificate records
`nginx -t && systemctl reload nginx` as its deploy hook, stored as `renew_hook`.
All three certificate-specific dry runs passed, including the deploy hook.

For a targeted renewal check:

```bash
certbot renew --dry-run --cert-name nodusnetwork.io --no-directory-hooks --no-random-sleep-on-renew --run-deploy-hooks
```

Use the Wiki or Scan certificate name when checking those. Do not run a blanket
renewal test for unrelated domains. `--no-directory-hooks` avoids executing the
existing unconditional mail hook; its configuration was not modified.
The HTTP ACME route remains available. All four hostname challenge paths were
verified through Cloudflare before issuance; no DNS-only transition was needed.

The certificates support Cloudflare Full (strict). The dashboard's exact SSL
mode was not inspected or changed. Public and direct-origin HTTPS were verified
with hostname validation; no certificate-verification bypass was used.

## Updates and verification

Read website/README.md validation guidance, then run from website/:

```bash
npm run build:portals
npm run check
npm run package
```

Transfer only the three generated public directories' contents with SCP.
Never use rsync or upload the full source tree, internal notes, manifest.json or
this directory into a public root. The initial package had 72 public files.
Public checks matched 69 files byte-for-byte; three robots.txt files retained
their original content after Cloudflare's managed prefix.

Back up affected Nodus configs before updates; run `nginx -t` before reload,
restoring just those files on failure. HTTP templates are bootstrap references;
do not enable HTTP and HTTPS templates together for the same domain.
Nginx reload sends a signal: verify the certificate actually served for each SNI
hostname before declaring the configuration ready. An immediate Wiki probe saw
the previous certificate; explicit subsequent SNI checks and verified HTTPS
confirmed all three new certificates.

One pre-install validation failed resolving the existing artifacts.cpunk.io
upstream, before live config changes. Server and public DNS checks subsequently
resolved its expected address and resumed validation passed. No CPUNK DNS
configuration was edited. Never mask configuration failures with retry loops.

## Backup and rollback

The initial Nginx snapshot and existing-site checksum manifest are in the
root-only `/var/backups/nodus-launch-20260914/` directory. It also contains
`bootstrap-sites/` and `before-no-transform/` configuration snapshots.
The transfer package and temporary install scripts are in the root-only
`/var/tmp/nodus-launch-20260914/` staging directory.

To withdraw this first deployment, disable only the three Nodus enabled-site
symlinks, validate Nginx and reload. Do not restore the whole snapshot over
unrelated changes or delete existing CPUNK files. Keep certificates and public
roots for investigation unless removal is separately intended. Future content
updates need backups of the affected public files.

## DNS

Porkbun is the registrar; Cloudflare is authoritative. User-supplied records:

| Type | Host | Value |
| --- | --- | --- |
| A | @ | CPUNK server's verified IPv4, supplied in the conversation |
| CNAME | www | nodusnetwork.io |
| CNAME | wiki | nodusnetwork.io |
| CNAME | scan | nodusnetwork.io |

All four are proxied with automatic TTL. No AAAA record was added. Public DNS
shows Cloudflare anycast addresses, not the configured origin value.

## Tokenomics removal — 15 September 2026

At the user’s request, updated 19 public files across the three sites and
removed `nodusnetwork.io/public/tokenomics.html`. The new package contains
71 files. Source hashes of all 20 affected existing files were verified before
writing; the uploaded package and all installed replacements also passed
SHA-256 verification. Nginx remained active; no configuration reload was needed.

The affected previous files are backed up, with their domain/public paths, in
`/var/backups/nodus-remove-tokenomics-20260915/`. The removed page is also saved
as `removed-tokenomics.html` there. The staging package and installation script
are in `/var/tmp/nodus-remove-tokenomics-20260915/`. Restore the backed-up files
to their corresponding `/var/www/` paths only if this removal is to be reversed.
The installer’s file list is `all-files.txt` in staging.

Public verification confirmed that all 19 changed files match the new package,
the former tokenomics URL returns 404 in EN/TR, and Scan’s GET API still returns
data with `Cache-Control: no-store`. Mobile and desktop publication checks and
the focused language-navigation check are recorded in `../REVIEW.md`.
