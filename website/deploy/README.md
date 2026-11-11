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

## Turkish copy revision — 23 October 2026

Published after the operator explicitly approved all three sites. Updated 41
public files: 18 main-site, 15 Wiki and 8 Scan. The package was
`/tmp/nodus-sites-3g17xU/`; only the selected public files were installed.
Existing source/baseline comparisons showed no unexpected concurrent changes.

Prior versions and the before/after SHA-256 manifest are backed up under
`/var/backups/nodus-turkish-20261023T134902Z/`. The root-only staging directory
`/var/tmp/nodus-turkish-20261023T134902Z/` contains the installer, manifest and
selected replacements. Assets were replaced before HTML, atomically per file,
with existing owner/mode retained. No Nginx reload or service restart was needed.
To roll back, restore only manifest-listed files from the domain directories
in this backup to their corresponding public roots, first checking that the
live hashes still match this deployment so later edits are not overwritten.

Fresh SSH readback and public HTTPS matched all 41 new hashes. JS/CSS were
requested with the content-version queries referenced by the generated pages;
HTML/search JSON were checked at their normal URLs. Current public JS/CSS
responses can be cached for four hours, while HTML/search JSON revalidate.
Live Chromium checks passed at 390/1440px on all three sites, including language
switch/reload; Wiki search/navigation and developers at 320px passed as well.
There were no request, JavaScript or UI errors in these live checks. Review
artifacts are in `/tmp/nodus-turkish-copy-aw9eXC/` in the operator workspace.

## swap.nodusnetwork.io — 10 November 2026

The operator added the Cloudflare record (proxied, like wiki and scan) and approved the install ("kur sen").
On EU-6 (`nodus-eu-6`), same host as the other sites:

- Document root `/var/www/swap.nodusnetwork.io/public`, root:root, 755/644. Content: the swap site
  visual draft (`index.html`, `swap.css`, Inter fonts, `nodus-mark.svg`), marked "Design draft · sample numbers";
  not connected to any service yet. CSS is in a file because the CSP allows only `style-src 'self'`.
- `/etc/nginx/sites-available/swap.nodusnetwork.io` + enabled symlink: first `swap-http.conf`, then
  `swap-https.conf` (the Wiki configuration with the name changed: same headers, CSP, GET-only).
- Certificate `swap.nodusnetwork.io`: webroot, the existing ACME account, ECDSA, `renew_hook = nginx -t && systemctl reload nginx`,
  issued with `--no-directory-hooks`; expires 2027-02-08. Targeted renewal dry run passed.
- Backups and checks: `/var/backups/nodus-swap-site-20261110/` (nginx checksums before/after: only the two swap
  entries are new; the HTTP-only config). Public files byte-identical (5/5); HTTP redirects to HTTPS; direct-origin
  HTTPS with hostname validation 200; nodusnetwork.io, wiki, scan, wallet, connect and cpunk.io still 200.

## Extension page corrections — 10 November 2026

Operator: "düzelt", "deploy et sonra". `extension.html` brought in line with the 0.1.162 store texts
(further networks, notifications, server choice, prices from DefiLlama, storage / timers / network-server
permissions), "not on BNB Smart Chain" for history (`web-wallet/src/capabilities.js:7`), "Chrome 123 or later"
(extension manifest), X card title/description matching Open Graph; Turkish keys in `app.js`; all 18 pages
load `app.js?v=e9e8316bf2f0`. On EU-6 (`nodus-eu-6`): 19 files backed up to
`/var/backups/nodus-site-20261110T181408Z-extfix/`, staged in `/var/tmp/nodus-site-20261110T181408Z-extfix/`,
installed root:root 644 (app.js first). Server 19/19 and public 86/86 (robots.txt excluded) match the package;
live Chromium 390/1440 × en/tr: no overflow, no errors.

## Swap bot on 62.171.136.77 (amm-https.conf)

`amm-https.conf` is the web server in front of the swap bot on the bot's machine (plan
`docs/plans/2026-11-08-swap-bot-plan.nodus1.md` section 4.1). The page stays on EU-6 (`swap-https.conf`, whose
`connect-src` is `'self' https:`); the browser and the extension call the bot directly at `https://62.171.136.77`.
It proxies only `/amm/` to the bot at 127.0.0.1:4011, answers the browser's OPTIONS question itself, adds
`Access-Control-Allow-Origin: https://swap.nodusnetwork.io` to every answer, and limits `/amm/quote` and
`/amm/liquidity/quote` to one question every 2 seconds per address (429 with `{"approved":false,"reason":"busy"}`).
It shares nginx with kayraninyeri.com: its other server blocks are not touched, but a broken file breaks both sites.

Files of this section: `amm-https.conf`, and in `amm-cert/` the reload script `amm-cert-reload.sh`, the service
`nodus-amm-cert.service` and the timer `nodus-amm-cert.timer`.

Install (on 62.171.136.77, as root; lego v5.6.0 is installed outside Debian 12's archive as `/usr/local/bin/lego`):

1. Back up `/etc/nginx`; read `nginx -T` for a name clash with the zone `amm_quote` and for any other
   `default_server` on `443`; `mkdir -p /var/www/acme-amm`.
2. Install the reload script and the units:
   `install -m 755 amm-cert/amm-cert-reload.sh /usr/local/sbin/amm-cert-reload`,
   `install -m 644 amm-cert/nodus-amm-cert.service amm-cert/nodus-amm-cert.timer /etc/systemd/system/`,
   `systemctl daemon-reload`. The script is the lego deploy hook: lego v5.6.0 splits a hook string on whitespace and
   runs it without a shell (`cmd/internal/hook/hook.go:23-25`), so `nginx -t && systemctl reload nginx` cannot be
   given to it inline.
3. First certificate. The standalone port-80 block `/etc/nginx/sites-enabled/amm-ip-acme` already answers the
   challenge, so no nginx change is needed yet. lego v5.6.0 has no `renew` command: `lego run` issues and renews, and
   its flags follow `run` (`docs/content/migration/cli.md:30-44`, `cmd/cmd_root.go:35-44`). The flags used exist in
   `cmd/internal/flags/flags.go`: `--path` (:769), `--server` (:232), `--accept-tos` (:720), `--domains` (:729),
   `--profile` (:641), `--http` (:327), `--http.webroot` (:354), `--deploy-hook` (:676). `--email` (:561) is optional:
   without it the account is stored under the default account name (`cmd/internal/storage/account.go:89-98`); add
   `--email <operator email>` only if the operator wants Let's Encrypt contact mail. A certificate for an IP address is
   issued only under the `shortlived` profile (about 6 days; http-01 on port 80; plan section 4.1). Staging first, in its
   own storage directory (Let's Encrypt staging directory `https://acme-staging-v02.api.letsencrypt.org/directory`,
   `lego/zz_gen_ca.go:107`):
   `lego run --path /etc/lego-amm-staging --server https://acme-staging-v02.api.letsencrypt.org/directory --accept-tos --domains 62.171.136.77 --profile shortlived --http --http.webroot /var/www/acme-amm --deploy-hook /usr/local/sbin/amm-cert-reload`
   Then production, the same command with `--path /etc/lego-amm` and
   `--server https://acme-v02.api.letsencrypt.org/directory` (`lego/zz_gen_ca.go:103`). The files appear as
   `/etc/lego-amm/certificates/62.171.136.77.crt` and `.key`, the names `amm-https.conf` uses. (The hook reloads nginx
   with the configuration that is installed at that moment; at this step that is the old one, which is harmless.)
4. In ONE step, remove the standalone port-80 block and enable the complete file (both declare `server_name
   62.171.136.77` on port 80, and nginx ignores the second one with a "conflicting server name" warning,
   `ngx_http.c:1518`): `rm /etc/nginx/sites-enabled/amm-ip-acme`,
   `cp amm-https.conf /etc/nginx/sites-available/amm-62.171.136.77`,
   `ln -s /etc/nginx/sites-available/amm-62.171.136.77 /etc/nginx/sites-enabled/`, then `nginx -t && systemctl reload nginx`.
5. Start the timer: `systemctl enable --now nodus-amm-cert.timer`. It runs the production `lego run` every 12 hours.
   The service runs lego's own renewal rule: a certificate not yet due is left alone (`cmd/cmd_run_renew.go:77-87`),
   and for a 160-hour certificate it is due 80 hours before expiry (`:299-312`), so 12 hours is well inside the
   window. After every run the service also runs the reload script (`ExecStartPost`), so nginx serves the certificate on
   disk even if an earlier hook failed. Rationale and citations are in the comments of the two unit files.
6. Check after the install:
   - the certificate actually served: `openssl s_client -connect 62.171.136.77:443 </dev/null 2>/dev/null | openssl x509 -noout -subject -dates`
     (names the IP address, the dates match the files under `/etc/lego-amm/certificates/`);
   - kayraninyeri.com still served with its own certificate:
     `openssl s_client -connect 62.171.136.77:443 -servername kayraninyeri.com </dev/null 2>/dev/null | openssl x509 -noout -subject -dates`;
   - `OPTIONS /amm/quote` answers 204 with the allow-origin header; two price questions inside 2 seconds give 200
     then 429 with the busy body; `https://62.171.136.77/` answers 404; kayraninyeri.com answers 200;
   - a staging renewal run: `lego run` with the staging command of step 3 and `--renew-force` (`flags.go` name
     `renew-force`, `cmd/internal/flags/names.go:160`) must write new files and run the hook without error;
     `systemctl start nodus-amm-cert.service` must end with `systemctl status nodus-amm-cert.service` showing success.
   A failed renewal makes the bot unreachable for browsers within days: `systemctl list-timers nodus-amm-cert.timer`
   and the served certificate's dates are the ones to read after each deploy.
