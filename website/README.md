# Nodus website

Standalone Nodus brand website, separate from the CPUNK sites. Static HTML, CSS,
and browser JavaScript; no runtime packages. Node.js 20 or newer runs the local
preview and the small static Wiki/Scan page generator.

Published on 14 September 2026: [Nodus](https://nodusnetwork.io/),
[Wiki](https://wiki.nodusnetwork.io/) and [Scan](https://scan.nodusnetwork.io/).
Hosting and update instructions are in [deploy/README.md](deploy/README.md).

## Run locally

```bash
cd /opt/dna/website
npm run dev
```

Open **http://127.0.0.1:4173**. Stop with Ctrl+C. An alternative port can be set
with `PORT=4174 npm run dev`. `HOST` defaults to `127.0.0.1`; bind to another
interface only when you intend to make the preview accessible there.

For another machine on the same local network, start with:

```bash
HOST=0.0.0.0 npm run dev
```

Then open `http://<this-machine-LAN-IP>:4173` on that machine. The user explicitly
requested LAN access on 2026-09-10; the current preview uses this binding.

The same preview also serves **`/wiki/`** and **`/scan/`**. It rewrites links
between the three Nodus domains to these local paths. Published HTML retains
the intended domains, `nodusnetwork.io`, `wiki.nodusnetwork.io` and
`scan.nodusnetwork.io`.

Scan's local `/scan/api/` proxy reads the existing `https://scan.cpunk.io`
explorer API. To use another indexer, set `SCAN_API_ORIGIN` to its HTTP(S) origin
when starting the server, for example `http://127.0.0.1:8390`. The proxy exposes
only the supported read endpoints. The browser makes same-origin requests.

## Wiki and Scan

- `wiki/`: 13 pages — a searchable home and 12 EN/TR guides. Edit the authored
  content in `wiki/content.mjs`, then run `npm run build:portals`.
- `scan/`: explorer home plus block, transaction and address pages. Its script
  uses the existing JSON API and keeps the current DNAC devnet unit. It does not
  rename backend fields or change consensus, the indexer, or the running chain.
- `build-portals.mjs`: shared HTML templates for both subdomains. Generates the
  guide search index and each subdomain's sitemap/robots files deterministically.
- `portal.css`, `portal.js`: shared typography, colors, responsive navigation,
  language handling and article navigation for the two subdomains.
- `public-files.mjs`: explicit public manifests for preview and packaging.
- `npm run package`: creates three independently deployable public directories
  under a new `/tmp/nodus-sites-*` path. Internal source notes, generators and
  deployment configs are excluded. Run after rebuilding edited guide templates.

Scan displays API failure separately from an empty chain or unknown values.
Amounts use integer formatting; non-native token amounts remain raw base units
because the API does not supply their decimals. Supply is labelled as current
devnet supply, not market circulation. The footer describes the indexer's trust
in witness responses. A successful HTTP request does not prove a chain is active;
block timestamps and the reported index position remain visible.

The server serves an explicit allowlist of public assets, supports GET/HEAD,
and sends a same-origin Content Security Policy. It does not expose source
files outside that allowlist. This server is for local previews.

## Pages and behavior

- `index.html`: a short introduction with routes to the products, resource
  network, manifesto, and roadmap.
- `ecosystem.html`: the product directory and FAQ. Six image-led product cards
  link to the individual pages. Connect and Scan have wider featured layouts.
  Each image represents its own product, and links work without JavaScript.
- `connect.html`, `wallet.html`, `identity.html`, `chain.html`, `scan.html`:
  individual product pages; Connect also hosts features and downloads.
- `network.html`: Storage, Bandwidth, Compute, and shared architecture.
- `manifesto.html`: privacy, identity ownership, and why Nodus is being built,
  followed by the Team section.
- `terms.html`, `privacy.html`: the app's Terms of Service and Privacy Policy,
  linked from every footer, not from the top navigation.
- `roadmap.html`: implementation history and status filters, displayed by month
  and year (or month ranges), followed by undated future plans.
- `docs.html`: developer reference, security scope, source and contribution links.
- `styles.css`: responsive design and locally served Inter fonts.
- `app.js`: English/Turkish switching, mobile navigation, FAQ,
  and roadmap filters.
- `network.js`: a procedural mesh sculpture with metallic lighting, rendered
  with Canvas 2D.
- `visuals.js`: one-time scroll reveals, pointer lighting/depth, reading progress,
  and reduced-motion handling.
- `assets/artwork/`: twelve original WebP artworks: two homepage compositions,
  six product illustrations, three network services and one manifesto scene.
  Product artwork appears in the directory and its matching detail page;
  unrelated products do not share images. Prompts and provenance are in its README.
- `assets/nodus-mark.svg`: a provisional website mark for the new Nodus identity.

The language switch is stored locally when storage is available and carried
between pages in `?lang=en` or `?lang=tr`. Blocked local storage does not prevent
switching. The animation and decorative effects respect reduced-motion preferences.
The hero’s sculpture and ambient movement can be paused,
and the canvas stops when outside the viewport or in a hidden tab. Its geometry is fixed;
it is decorative, not live network data.

All marketing-page assets are local. No analytics, tracking, CDN, remote API, wallet
connection, mailing-list form, or transaction functionality is included.
External requests occur only if a visitor follows a repository, existing
release, or existing explorer link.

The Scan application additionally requests ledger data through the local proxy
described above. Production Nginx uses the existing loopback indexer and marks
API responses `no-store`.

## Content and naming

The user confirmed **Nodus / NODUS**, to take effect with the testnet transition.
The chain is currently **devnet**, using DNAC. This explicit user correction
takes precedence over stale Testnet labels elsewhere in the repository.
The website presents the proposed Nodus product family without renaming the
native binaries, protocol identifiers, source directories, or existing releases.

Product content was compared with CPUNK pages, public GitHub, and local
protocol/design/status/handoff records and git history through 10 September. See [CONTENT_SOURCES.md](CONTENT_SOURCES.md) for the complete page
mapping, pinned GitHub revision, differences checked in local code, and claims
that were corrected or excluded. The native libraries are Apache 2.0; the
Flutter app is proprietary source-available. Public channels are currently
disabled. Ledger V2 has implemented local milestones; the CometBFT reference
port is current consensus work. Shielded-payment integration remains future work.

The manifesto carries the CPUNK belief “Privacy is a human right” into the new
Nodus identity. Storage exists as application infrastructure; capacity trading,
Bandwidth services and the Compute market are planned. Tokenomics content was
removed from the public sites on 15 September at the user’s request. The earlier
allocation record remains internal history in CONTENT_SOURCES.md.

The page makes no live usage, price, throughput, mainnet, or launch-date claims.
The product graphics are illustrations. Product pages distinguish existing
DNA-branded releases from the new website branding. The purchased public domain
is `nodusnetwork.io`; canonical URLs, sharing metadata, robots.txt and sitemap.xml
use its HTTPS origin. Navigation and assets remain relative for local previews.
Existing GitHub links intentionally still point at the current repository.
The installed Nginx configurations and DNS instructions are in
[deploy/README.md](deploy/README.md).

## Validation

Before running checks, read this section in full. This is an isolated static
website; the C/Flutter suites do not exercise it and are not needed for it.

```bash
npm run check
```

This checks JavaScript syntax only. Browser verification additionally covers:

1. All 13 marketing pages at 320, 390, 768, 1024, and 1440 pixels, in both
   languages: no page overflow, missing assets, or browser errors.
2. Product cards navigate to dedicated pages; browser Back returns to the
   directory. Every local page/fragment target resolves. Direct page loads work
   without JavaScript, and old homepage bookmarks reach the replacement pages.
3. Mobile navigation: opening, following a link, and closing with Escape.
4. Language switches, reloads, and navigation between pages retain the selection across all pages.
5. FAQ answers open and close, and reduced motion keeps the sculpture static.
6. The server returns 404 for files outside the public allowlist and 405 for
   unsupported methods; successful asset responses include the correct types.
7. Roadmap filters show the selected status, retain it when changing language,
   and distinguish month/year history from undated future services. The removed
   tokenomics page returns 404 and has no published links, content or search entries.
8. Artwork loads with correct MIME types; the directory contains six distinct
   pictures matched to the six products. Pointer depth resets on
   leave, scroll reveals remain keyboard accessible, and reduced motion disables
   decorative movement.
9. Every translated text has a Turkish entry; local links and documentation
   targets resolve; release and explorer buttons use the documented URLs.

Use headless Chromium in this workspace. Browser checks must not launch a GUI
or click external links. A local preview proves the website works locally; it
does not validate public hosting, a purchased domain, or the underlying chain.

Validation completed on 2026-09-11 with Node.js 22 and headless Chromium.
All 120 page/language/viewport combinations passed, as did product navigation,
browser Back, language persistence, month/year roadmap filters, allocation
arithmetic, legacy bookmarks, JavaScript-disabled page loads, reduced motion,
and server allowlist checks. The initial eleven artwork files decoded successfully.
Pointer lighting/depth, reset on leave, scroll
reveals, progress, and reduced-motion behavior passed. Desktop pointer capability
was explicitly configured in headless Chromium for the hover checks. No browser
errors or external asset requests were observed. Desktop and mobile screenshots
were visually reviewed. A comparison with the pre-refresh snapshot also verified
that authored page copy was preserved, excluding replaced decorative illustrations.

## Change record

2026-09-10: Created a local, independent Nodus website at the user's request,
with bilingual content and the confirmed devnet/testnet naming transition.
Atlas repository/decision/file context was consulted. The session's Atlas
connector exposes no change-reason write tool, so this reason is recorded here.

2026-09-10: Expanded the website at the user's request after comparing CPUNK
pages with GitHub and current local code. Added Identity, Scan, practical app
features, release navigation, architecture, development status, security scope,
licenses, and contribution paths in English and Turkish. See CONTENT_SOURCES.md.

2026-09-10: Added the Nodus resource-network story, a full manifesto, dated
milestones from October 2025 through September 2026, current consensus work,
and the planned testnet allocation. Applied the user’s Community airdrop naming
and revised Bandwidth/developer/liquidity shares. Updated English and Turkish,
the allocation chart, and developer copy together. Original source planning
records were preserved; CONTENT_SOURCES.md records the newer user direction.

2026-09-10: Reorganized the long homepage into 12 standalone pages after the
user asked why the whole site was on one page. Product cards now navigate to
product pages instead of opening dialogs. Shared navigation, titles, language
persistence and the preview allowlist cover every page. Old homepage bookmarks
redirect to their new pages. Roadmap labels now show months and years, as the
user requested; commit dates remain in the internal source ledger as evidence.

2026-09-11: Refined the existing dark/lime design with original material artwork,
a featured Connect card, larger service images, sculptural product cards,
cinematic hero lighting, pointer-reactive highlights and depth, scroll reveals,
and reading progress. All enhancements preserve the multipage structure, monthly
roadmap and token allocation. Native image generation produced eleven artworks;
compressed workspace copies are served locally. Full prompts and source paths:
[artwork/README.md](assets/artwork/README.md). The imagery is decorative and makes
no new product or hardware claims.

2026-09-11: Replaced repeated decorative imagery after the user rejected reuse
across unrelated subjects. Added two homepage compositions, distinct artwork for
Connect, Wallet, Identity, Chain and Scan, and a separate human-scale manifesto
scene. The original three service images now appear only on the network page.
The product directory retains its own code-native illustrations; the tokenomics
chart has no recycled artwork. Product artwork preserves the full composition
at every viewport instead of cropping the subjects.

2026-09-11: Rebuilt Products after the user rejected the oversized illustrated
cards. Replaced the card grid and floating decorative objects with a structured
catalog: a Connect feature panel, related Wallet/Identity entries, compact
Chain/Scan rows and a Network overview. Copy now explains the product relationships
and capabilities directly; existing generated artwork remains on its original
pages. New content is authored in English and Turkish. Atlas context for HTML,
CSS and the translation file returned no decisions; this is the change record.

Targeted catalog verification passed in both languages at 320, 390, 768, 1024
and 1440 pixels: all six product links, browser Back, section anchors, translation
completeness, language persistence, keyboard focus/navigation and no-JavaScript
navigation. No overflow, browser errors or external asset requests were observed.
JavaScript syntax checks passed; desktop and mobile screenshots were reviewed.

2026-09-11: Corrected the preceding catalog interpretation after the user clarified
that pictures should replace the old illustrations. Restored the pre-catalog
layout and original product copy. Connect, Wallet, Identity, Chain and Scan now
use their accepted product pictures in the directory; Network has a new matching
illustration. Removed the rejected catalog CSS and translations. These are six
different product pictures, without sharing imagery between unrelated products.
Atlas context returned no decisions; the repository overview was stale, so local
files and the pre-catalog snapshot were used as the source of truth.

The image-based Products page passed both languages at all five documented
widths. All six distinct pictures decoded, matched their products, and retained
the original page copy. Product links, browser Back, language persistence,
keyboard and no-JavaScript navigation passed, with no browser errors or external
asset requests. Desktop and mobile screenshots were visually reviewed.

2026-09-11: Prepared the purchased nodusnetwork.io domain in all twelve pages,
including canonical URLs, sharing metadata, a JPEG preview, robots.txt and
sitemap.xml. The targeted domain check passed canonical and sharing URLs,
image MIME and dimensions, sitemap entries, robots, Turkish navigation, and
private-file exclusion. Local assets produced no external requests. Read-only
inspection confirmed Nginx 1.26.3 and Certbot on the intended CPUNK host. Added
separate HTTP/HTTPS configuration drafts and prepared an allowlisted public
package; server installation, DNS changes and certificate issuance were pending
at that point.

2026-09-11: Added the requested Nodus Wiki and Scan sites and reviewed all main
site pages. Reused the CPUNK wiki's topic coverage and the explorer's documented
API; authored clearer bilingual guides and a Nodus explorer interface. The main
site now links to both subdomains and its monthly consensus milestone includes
the R2 core that landed on 11 September. Corrected stale naming and supply copy,
recovery/privacy overclaims in migrated guides, and duplicate CTA arrows.
The accepted product-image layout remains in place. Atlas file context supplied
no website decisions; this record and CONTENT_SOURCES.md capture the reasons.

The review and validation record is [REVIEW.md](REVIEW.md). At that stage all
changes were local; production publication followed on 14 September.

2026-09-14: Published the 72-file public package after explicit user approval.
Installed three dedicated Nginx sites and Let's Encrypt certificates; verified
public and direct-origin HTTPS and all three renewal dry runs with deploy hooks.
Existing CPUNK vhost checksums stayed identical. Added no-transform headers after
the production browser identified Cloudflare's automatic analytics injection;
kept the local-only CSP and made Scan API responses non-cacheable. Native
components, the indexer and its database were not modified.

Production browser verification passed all 29 pages in EN/TR at 390 and 1440
pixels, including decoded images, internal links and the active CSP. Wiki search
retained Turkish on navigation; Scan pagination, block search, transaction and
address details passed against the live indexer. No browser errors, failed
requests or external asset requests remained. Fresh public-site screenshots
were captured and visually reviewed.

2026-09-15: Removed tokenomics at the user’s request: the page, navigation and
homepage links, developer allocation copy, Wiki allocation section and related
search entries, metadata, sitemap entry, translations and unused chart styles.
The public sites now contain 11 marketing pages, 13 Wiki pages and 4 Scan pages.
Atlas file context returned no governing decisions. This connector has no
change-reason write tool; this paragraph records the reason.

2026-09-23: Moved the app's Terms of Service and Privacy Policy from cpunk.io to
this site as `terms.html` and `privacy.html`, in English and Turkish, and added
Terms and Privacy links to every marketing-page footer. Added a Team section at
the end of `manifesto.html` with the two entries the operator supplied. Reason:
the operator decided that Nodus is separate from CPUNK (ledger section SITE-0923
in `tasks/orchestration.md`). The legal party is Nodus Foundation and the contact
is `legal@nodusnetwork.io`. Both new pages are registered in `public-files.mjs`,
`sitemap.xml` and the language-carrying page list in `app.js`. The main site now
has 13 marketing pages. Not yet published: publication waits until the
`legal@nodusnetwork.io` mailbox exists. Browser validation has not been run for
this change. Porting details are in CONTENT_SOURCES.md.
Operator follow-up the same day: the privacy policy now states that connected nodes can see IP addresses and connection timing, that channels are currently disabled, and that iOS Keychain applies only to the planned iOS version; the second Team entry is Ios “bios” Santelli.
