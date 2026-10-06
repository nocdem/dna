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
- `scan/`: explorer home, Statistics, block, transaction, address and hard forks pages. Its script
  uses the existing JSON API and labels the native coin NODUS. It does not
  rename backend fields or change consensus, the indexer, or the running chain.
  The script also renders the hard forks page (`data-page="hardforks"`, into
  `#hardforks-content`) from the explorer's `/api/governance`: a "Hard forks"
  table — HF-1 gas price (param 5, set by the genesis document: a fixed row,
  value 121, effective at block 0), HF-2 governance by stake weight (param 7),
  HF-3 consensus-only block bounds (param 8), HF-4 rule-set generation 2 +
  on-chain names (param 9), each with its rule in one sentence (from
  `nodus/docs/DEPLOY_RUNBOOK.md` §2.2 "Live hard forks"), vote block,
  effective block and status — Active when the reported `tip` ≥ the effective
  block, else Pending with the blocks left and a time estimate at ~60 s per
  idle block — and "Other governance changes" for every other vote
  (including a later gas-price change on param 5), param shown by name.
- `build-portals.mjs`: shared HTML templates for both subdomains. Generates the
  guide search index and each subdomain's sitemap/robots files deterministically.
- `portal.css`, `portal.js`: shared typography, colors, responsive navigation,
  language handling and article navigation for the two subdomains.
- `public-files.mjs`: explicit public manifests for preview and packaging.
- `npm run package`: creates three independently deployable public directories
  under a new `/tmp/nodus-sites-*` path. Internal source notes, generators and
  deployment configs are excluded. Run after rebuilding edited guide templates.

Scan's home page contains search, index status and the Latest blocks list.
It loads `/api/stats` for synchronization and pagination, but does not request
TPS or payday history. The navigation's Statistics / İstatistikler link opens
`scan/stats.html`, which contains supply, throughput, APY and paydays. Both
pages refresh every 30 seconds while visible (home only on block page 1),
and have a manual Refresh button. Statistics has no block pager.

Scan displays API failure separately from an empty chain or unknown values.
Amounts use integer formatting; non-native token amounts remain raw base units
because the API does not supply their decimals. The Statistics page shows two
cards — Indexed height and a combined Total supply / Circulating supply
(`supply_genesis` / `circulating`) pair with one shared NODUS suffix.
The Details button below the pair opens the "Where the supply is" table:
Validator rewards remaining (`reward_pool`), Storage, Compute, Bandwidth,
and Future services (`treasury` pools 1-4) — decision
`2026-09-30-scan-supply-buckets`; circulating
includes staked coins and the Foundation's coins. A `null` field (an older
node) shows "—" independently for each amount. The supply card gets twice
the height card's width on desktop; the two cards stack below 800 px and
the supply pair can wrap. Below the table a link leads to the main site's
`tokenomics.html` for how the supply is allocated. A "Throughput" section
follows (explorer `/api/tps`): Last minute and Last hour TPS cards and a
24-bar inline SVG chart of the last 24 UTC hours (oldest first, the newest
bar the hour in progress; each bar has a tooltip with the hour, its TPS and
its transaction count; the SVG carries an EN/TR `aria-label` naming the
peak hour). TPS counts applied transactions only and is measured by block
time up to the newest indexed block, not the visitor's clock. The chart
uses SVG presentation attributes (no `style`, CSP `style-src 'self'`) with
the `--lime` / `--line` colours read from `portal.css`. It loads with the
other Statistics figures (Refresh and the 30 s refresh) as its own
request: a failing or missing `/api/tps` shows "—" and a message in the
chart slot without affecting the rest of the page. Below the cards, from the
same response: "Next payday" — `block N — est. YYYY-MM-DD HH:MM UTC (≈ …)`
(`next_payday`: the next multiple of 17 280 blocks, estimated at the current
block pace from the newest indexed block; "no block pace yet" without one) —
and "Estimated APY at the current block pace" (`apy.apy` with a `%`, "—"
when the explorer could not compute it), each with a one-line note: the date
moves later when the chain is idle; the APY is before validator commission,
participation rules apply, fees are not counted. The "Paydays" table loads
independently from `/api/paydays?limit=25`: newest first, block, UTC time,
total paid and recipient count. "Load older paydays" follows `next_before`.
Automatic refresh preserves expanded history;
manual Refresh starts again with the latest paydays. A failed payout request
leaves TPS and APY alone. A historical summary with `available: false` shows
"Unavailable", never zero.

Payday block pages load `/api/payday/<height>?limit=100` and show recipient
addresses and amounts, with a separate `next_from` pager. Address pages load
`/api/rewards/<fingerprint>?limit=25` and show recorded payouts, pending next
payout, and a dated payout history with block links. Its `next_before` cursor
is a literal `height:sequence`, independent of transaction history. All amounts
are decimal strings of integer base units, formatted with BigInt at 8 decimals.
Recorded payouts are the sum within the available history starting at
`from_height`, not a lifetime total or wallet balance. Paid rewards are already
included in the balance while unspent; pending rewards are not yet spendable.
EN/TR coverage labels show the history's starting block and `at_height`, the
source height of pending rewards on address pages (which can be ahead of the
transaction index). Payout list and block-detail responses are bounded by the
indexed height. Loading, empty results and unavailable sources have distinct
states; a failed subsequent page preserves already displayed records.
Each payout pager keeps the first page's totals, pending rewards and coverage
stamp while loading older records. Later pages must have the same
`from_height` and an `at_height` at least as recent as that first page; otherwise
the page asks for Refresh and leaves the existing rows and summary intact.
A newer source tip does not replace the initial summary with figures for
paydays missing from the top of the displayed history. Refresh starts a new
snapshot.

Stake releases — the validator bonds and delegations returned at an epoch
boundary — have their own sections. Every block page whose height is a
multiple of 720 loads `/api/releases/<height>?limit=100` and shows a
"Stake released / Serbest bırakılan stake" section: the line
"Stake released: N, total X NODUS" (`count`, `total`), the owner addresses
and amounts, and a separate `next_from` pager ("Load more stake releases").
A payday block (a multiple of 17 280) shows both the payout and the release
sections. Address pages show a second "Stake released" section from the
`releases` list of `/api/rewards/<fingerprint>?limit=25` — the total
(`released_total`) and a dated list with block links, paged by its own
`release_before` cursor (`next_release_before`), independent of the payout
list. A release is the owner's own stake coming back, not a reward; Scan
never adds it to the payout figures, and an EN/TR note says so. The node
records bond and delegation releases under one kind, so Scan does not tell
them apart. The release pagers keep the same snapshot, empty, loading and
unavailable states as the payout pagers, with their own EN/TR texts.

Payouts occur at the block boundary and remain separate from transactions.
The footer describes the indexer's trust
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
- `connect-soon.html`: the Nodus Connect coming-soon page (first to the web,
  inside the Nodus web wallet; same 24-word recovery phrase; DNA Connect apps no
  longer distributed), with a button to the web wallet. Reached from the
  Products menu.
- Header: the top navigation is grouped into four menus — Products (Web wallet
  at `https://wallet.nodusnetwork.io/`, Nodus Connect "preview" → `https://connect.nodusnetwork.io/`,
  All products → `ecosystem.html`), Network (`network.html`, `tokenomics.html`,
  `airdrop.html`, Scan), About (`manifesto.html`, `roadmap.html`) and Developers (`docs.html`,
  Wiki). Each menu is a button with `aria-expanded`; it opens on hover with a
  desktop mouse, on click/tap and with Enter/Space, and closes with Escape, on
  an outside click or when focus leaves it. In the mobile menu the groups expand
  inline. Without JavaScript the desktop menus open on hover and keyboard focus.
  The header button is "Open Wallet" → the web wallet (hidden at 1100 px and
  below, where the Products menu carries the same link). Every footer also has
  a Web wallet link. All 16 pages carry the same header; only the current
  page's link (`aria-current`) and group (`current-section`) differ.
- `network.html`: Storage, Bandwidth, Compute, and shared architecture.
- `manifesto.html`: privacy, identity ownership, and why Nodus is being built,
  followed by the Team section.
- `tokenomics.html`: the fixed NODUS supply, its eleven allocations, how the
  testnet genesis holds them, validator rewards, a plain-language earning
  guide (how to earn NODUS, epochs and paydays, how a reward is calculated,
  running a validator, delegating, roles, and planned changes clearly marked
  as not live), and the circulating-supply definition; current figures are
  linked on Scan. Linked from the top
  navigation and every footer.
- `airdrop.html`: the general Airdrop page, whose content begins with
  "First airdrop: CPUNK community." The page and menu remain "Airdrop";
  the introduction mentions that other campaigns will follow.
  CPUNK-specific sections explain what the first campaign is (paid daily over
  365 days, start to be announced), which CPUNK
  counts (only the CPUNK address of the holder's own Nodus Connect wallet),
  how a share is worked out (whole units of 1,000,000 CPUNK, the day's lowest
  balance), the six steps from creating a Nodus Connect account to claiming
  every day, how registrations and payouts are checked, and a safety note.
  The first campaign's 10,000,000 NODUS amount remains visible. The overall
  airdrop budget is on `tokenomics.html#allocation`, linked from More.
  Future campaign dates and eligibility are not specified.
  Linked from the Network menu (after Tokenomics) and every footer.
- `terms.html`, `privacy.html`: the app's Terms of Service and Privacy Policy,
  linked from every footer, not from the top navigation.
- `roadmap.html`: implementation history and status filters, displayed by month
  and year (or month ranges), followed by undated future plans.
- `docs.html`: developer reference, security scope, source and contribution links.
- `styles.css`: responsive design and locally served Inter fonts.
- `app.js`: English/Turkish switching, mobile navigation, header menu groups,
  FAQ, and roadmap filters.
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
The chain has been a **testnet** since 30 September 2026 (it was devnet until
then, and the site's labels were changed from devnet to testnet the same day);
some code and tools still use the DNAC name.
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
allocation record remains internal history in CONTENT_SOURCES.md. On 30 September
the operator asked for a new tokenomics page; `tokenomics.html` was written fresh,
not restored. Every number on it comes from the operator's tokenomics decision
(2026-09-22), the testnet genesis configuration and the Scan supply-buckets
decision (2026-09-30); reward mechanics are stated only where that decision and
the current chain code agree. The page says plainly that the chain is a testnet
and makes no price, value, return or mainnet statement.

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

1. All 16 marketing pages at 320, 390, 768, 1024, and 1440 pixels, in both
   languages: no page overflow, missing assets, or browser errors.
2. Product cards navigate to dedicated pages; browser Back returns to the
   directory. Every local page/fragment target resolves. Direct page loads work
   without JavaScript, and old homepage bookmarks reach the replacement pages.
3. Mobile navigation: opening, following a link, and closing with Escape.
   Header menu groups: mouse hover, click/tap, Enter, Escape (closes the open
   group first, then the mobile menu) and outside click; inline expansion in
   the mobile menu.
4. Language switches, reloads, and navigation between pages retain the selection across all pages.
5. FAQ answers open and close, and reduced motion keeps the sculpture static.
6. The server returns 404 for files outside the public allowlist and 405 for
   unsupported methods; successful asset responses include the correct types.
7. Roadmap filters show the selected status, retain it when changing language,
   and distinguish month/year history from undated future services. The
   tokenomics page (re-added 30 September) is reachable from the navigation,
   every footer and the Scan supply details, and its allocation table sums to
   1,000,000,000 NODUS / 100%.
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

2026-09-30: Added a new `tokenomics.html` at the operator's request, written
fresh (the 15 September page was not restored), in English and Turkish. It
shows the fixed 1,000,000,000 NODUS supply and its eleven allocations from the
operator's tokenomics decision of 22 September, how the testnet genesis holds
them (reward reserve, four keyless service pools, Foundation 2-of-3 multisig
coins, seven genesis validator stakes, the Founder's claimable allocation),
the validator reward mechanics on which that decision and the current chain
code agree, and the circulating-supply definition from the Scan supply-buckets
decision. Current figures are linked to Scan; Scan's supply details link back
to the page. Tokenomics sits after Network in the top navigation and every
footer. Registered in `public-files.mjs`, `sitemap.xml` and the
language-carrying page list in `app.js`. The main site now has 14 marketing
pages. Also corrected the stale "devnet" line under Content and naming.
Browser validation has not been run for this change.

2026-09-30: At the operator's request ("group the links at the top, put the
wallet link there, and a coming-soon page for Connect") the eight flat header
links became four menu groups (Products, Network, About, Developers), the
header button now opens the web wallet, every footer gained a Web wallet link,
and `connect-soon.html` was added in English and Turkish. Its copy reuses the
existing `soon.*` strings; it makes no new product claims. Registered in
`public-files.mjs`, `sitemap.xml` and the language-carrying page list in
`app.js`. The main site now has 15 marketing pages; `connect.html` is unchanged
apart from the header and footer. A targeted headless-Chromium check ran on the
local preview: all 15 pages in Turkish (four groups, no browser errors),
hover/click/Enter/Escape/outside-click at 1440 px, the inline mobile menu at
390 px, and no horizontal overflow at 390, 1101, 1150, 1280 and 1440 px. The
full five-width × two-language matrix above was not re-run.

2026-10-01: Completed the search metadata at the operator's request ("is the
SEO done? … complete it"). Every page already had a title, description,
canonical URL, Open Graph and Twitter card tags, and robots.txt/sitemap.xml
existed. Added to `index.html` one JSON-LD block (`application/ld+json`) with
an `Organization` (name Nodus, the site URL, `assets/nodus-mark.svg` as logo,
the GitHub repository as `sameAs`) and a `WebSite` entry; Google lists SVG
among the image formats it accepts for the logo. A JSON-LD block is a data
block, not a script, so the site's `script-src 'self'` CSP still applies
unchanged. `sitemap.xml` now carries a `<lastmod>` per URL, taken from the
page's last commit date; update it when a page changes. Not done: the Wiki and
Scan sitemaps (generated by `build-portals.mjs`) have no `lastmod`; there is no
`hreflang`, because Turkish is a client-side switch on the same URL; Search
Console ownership is the operator's account and is not set from the site.
A headless-Chromium load of the local preview showed the block in the page and
no CSP refusal; `npm run check` passed.

2026-10-03: Added `airdrop.html` at the operator's request, in English and
Turkish (`air.*` strings and `nav.airdrop` in `app.js`), modelled on
`tokenomics.html`. Every statement on it comes from the facts the operator
supplied for the page; at that time it added no amounts beyond the 1,000,000
CPUNK unit, no percentages, no dates and no price or value statements. The
amount/percentage restriction was superseded for the budget figures on
5 October 2026, as described above. An "Airdrop" link was
added to the Network menu (after Tokenomics) and to the footer of every page,
and the page was added to `sitemap.xml`. The main site now has 16 marketing
pages. Not done in this change: the page is NOT yet registered in
`public-files.mjs` (so the local preview returns 404 for `/airdrop.html` and
`npm run package` leaves it out) nor in the language-carrying page list
(`sitePages`) in `app.js`; both were outside the approved file list. The other
pages' `<lastmod>` dates in `sitemap.xml` were not changed. Browser validation
has not been run for this change.

2026-10-03: At the operator's request ("update the Wiki and the Roadmap and
everything with the things we built recently") the Wiki guides, the roadmap
and the sentences on the product pages that the recent work made untrue were
updated, in English and Turkish. Every item carries its status, grounded as
follows: LIVE = deployed per the release commits and the deploy records
(web wallet / Nodus Connect 0.1.45–0.1.52, the last 446e3c4c; explorer 0.2.1
with `/api/tps`; the Scan hard forks page; the tokenomics earning guide; the
airdrop page) and the "Live hard forks" table in
`nodus/docs/DEPLOY_RUNBOOK.md` §2.2 (HF-1..HF-4, HF-4 effective at block
3,151); BUILT-NOT-LIVE = the Nodus component split (nodus 0.23.17, merge
b72c3de6, whose message says no live node runs it) and the airdrop
registration/claim; PLANNED = the HF-5 decisions in
`docs/plans/decisions/2026-10-03-role-stake-amounts.md` (2,000,000 bond,
role stakes, 10% power cap, separate owner key). Name rules and prices are
from `docs/plans/decisions/2026-10-02-onchain-names.md` items 4–6, 10, 11 and
16 and `dnac/include/dnac/dnac.h` (`DNAC_NAME_PRICE_*_DEFAULT`; no price
vote is in the runbook table).
- `roadmap.html` / `app.js` (`history.*`): the multisig item moved from
  planned to built (shared vaults, 3 October); new built items for Scan
  (hard forks page, chain-name search, throughput, paydays, APY estimate)
  and for the component split (labelled "built, not yet on the live nodes";
  nodus-connect dropped from it — that component is still undecided); the
  names item gained the prices; "Nodus in the browser" gained send-to-name,
  the address book and chain names in Connect; a new in-progress airdrop
  item (no amounts, no dates); the roles item gained the vote-changeable
  amounts, the 10% power cap, the separate owner key and "only with a
  voted hard fork".
- `docs.html`, `chain.html`, `wallet.html`, `connect.html` / `app.js`:
  "Nodus Connect is coming first to the web" → open on the web as a preview;
  "Sending NODUS from Connect is not yet available" and "coin transfers are
  built with nodus-cli; the wallet path is still in development" → NODUS is
  sent from the web wallet and Nodus Connect (preview), or with nodus-cli
  (keys `docs.transitionBody`, `product.connect.note`, `docs.walletBody`,
  `everyday.networksBody`, `docs.chainBody`, `docs.engineCli`).
- `wiki/content.mjs`: Getting started and Recovery point to Nodus Connect
  as an open preview; Identity gains "Chain names"; Wallet gains "In the web
  wallet and Nodus Connect" (send to a name, address book, Earn, shared
  vaults, chain name) and loses the "cannot send NODUS" sentences; Chain &
  NODUS gains "Hard forks on the testnet", "Earn NODUS" and "Planned, not
  live"; The resource network gains "Running a node" (split built, not live);
  Using Nodus Scan gains "Throughput and paydays", "Hard forks page", the
  name search and the name on transaction pages; Build with Nodus lists
  `/api/tps`. No new guide page: the Wiki still has 13 pages.
- This file: the header line now names Nodus Connect "preview" →
  `https://connect.nodusnetwork.io/` (it still said "soon" →
  `connect-soon.html`). The roadmap change of the same morning (6e56cb39)
  had no change record here.
Not done (outside the approved files): `identity.html` still describes only
the DHT name; `sitemap.xml` `<lastmod>` dates were not changed; `/airdrop.html`
is still missing from `public-files.mjs` and from `sitePages` in `app.js`.
`npm run check` and `npm run build:portals` were run; browser validation has
not been run for this change.

2026-10-04: The roadmap, the tokenomics page and the Wiki were updated, in
English and Turkish, with what changed since 7a8e33c8. Status grounding:
LIVE = block pruning in nodus 0.23.18 on all seven testnet nodes (pruned
validators keep the last 7 paydays, 120,960 blocks, plus the genesis link;
archive nodes keep everything; every node drops the duplicate seen-commit
copy; pruning switched on on one node first, the others after it is
checked — `nodus/docs/DEPLOY_RUNBOOK.md` §2.5) and web wallet / Nodus
Connect 0.1.53–0.1.54 (one name per contact: chain name, else profile
name, ID underneath; Connect opens from what the device keeps and connects
in the background, sending waits until connected — `web-wallet/README.md`
"Nodus Connect"); PLANNED = the storage role reward (design approved
2026-10-04, being built, switched on later by a hard fork that validators
vote in: a 1,000,000
NODUS storage-role stake, an equal share of the Storage pool when validators
confirm the node serves stored data, no storage reward for validators, a
storage node and a validator may be the same machine). No node is named and
no address is published.
- `roadmap.html` / `app.js` (`history.*`): "Pruning and a block archive"
  moved from planned to implemented (4 October 2026) and rewritten — its old
  text said storage nodes keep the archive; "Nodus in the browser" gained
  the one-name rule and the local-first open; new planned item "Storage role
  reward" (`history.storage_reward.*`) after the roles item.
- `tokenomics.html` / `app.js` (`tok.plannedStorage`): the planned storage
  reward no longer says it also goes to validators; it now states the
  storage-role rule above.
- `wiki/content.mjs`: Identity "Chain names" states the one-name rule;
  Wallet "In the web wallet and Nodus Connect" gains the quick start; The
  resource network "Running a node" gains "Block retention"; Chain & NODUS
  "Planned, not live" gains the storage role reward. Generated wiki pages and
  `wiki/search-index.json` rebuilt with `npm run build:portals`.
- `sitemap.xml`: `<lastmod>` 2026-10-04 for `roadmap.html` and
  `tokenomics.html`.
`npm run check` and `npm run build:portals` were run; browser validation has
not been run for this change.


2026-10-05: Clarified the general Airdrop program and the first CPUNK Community
Airdrop in English and Turkish. Published the operator-approved 5% total / 1%
CPUNK / 4% future-campaign budget, all measured against total NODUS supply.
Tokenomics retains eleven allocations totalling 1 billion NODUS / 100%; the
Roadmap entry stays in progress and retains its start-to-be-announced wording.
Also corrected Tokenomics' Current figures link and instructions to use Scan
Statistics and its five-row Details list after the requested Scan page split.
The document column can shrink within its grid, keeping wide tables inside
their horizontal scroll area on narrow screens.

2026-10-05 follow-up: At the operator's request, removed the Airdrop budget
section, its sidebar link and repeated budget summary from `airdrop.html`.
The first content section is now the CPUNK campaign overview. Tokenomics
retains the budget figures and links directly to `airdrop.html#overview`.

2026-10-05, hard forks section: `roadmap.html` gains a "Hard forks: live and
planned" section (`#hardforks`, `forks.*` keys; Turkish in `app.js`), at the
operator's request ("bu paketleri internete siteye koymak lazım, planlananları
da"; placement chosen: the roadmap). LIVE rows HF-1..HF-4 are copied from the
"Live hard forks" table in `nodus/docs/DEPLOY_RUNBOOK.md` §2.2 (vote and
effective blocks 0/0, 724/1,500, 2,206/2,926, 2,431/3,151). PLANNED: HF-5 =
Nodus EVM and HF-6 = the role-stake package (operator numbering decision
`docs/plans/decisions/2026-10-05-hf-numbering-evm-hf5.md`; the earlier "HF-5"
name of the role-stake decisions in `2026-10-03-role-stake-amounts.md` is now
HF-6), and the storage role reward, which takes the next number when ready.
The Nodus EVM text rests on the Nodus EVM branch's Prague state-test run
(17,265 pass, 0 fail, 9 documented EIP-7823 modexp deviations; blob and
set-code transactions excluded by design) — built, not released, not voted.

2026-10-05, correction (operator: "hard forks diye bir bölüm vardı"): the
roadmap "Hard forks" section above duplicated the Scan Hard forks page and the
Wiki's "Hard forks on the testnet" / "Planned, not live" sections, and was
removed. Instead: Scan `hardforks.html` gains a static "Planned hard forks"
list under the live table (`build-portals.mjs`, `planned`), the Wiki's
"Planned, not live" names HF-5 (Nodus EVM, new item) and HF-6 (the four
role-stake items) and says the storage reward takes the next number, and the
roadmap keeps one planned item `history.evm.*` ("NEXT · HF-5") with the roles
item dated "LATER · HF-6". Numbering per
`docs/plans/decisions/2026-10-05-hf-numbering-evm-hf5.md`.

2026-10-05, one roadmap item per hard fork (operator: "git geçmişinden HF'leri
bul. her birini yaz o zaman roadmap'e. bundan sonra da ekleyelim"): the single
"Four hard forks active on the testnet" item (`history.forks.*`) is replaced by
`history.hf1..hf4.*`, each dated by the commit time of its effective block
(Scan `/api/block/<h>`: block 1 2026-09-30 10:00 UTC, 724 2026-09-30 23:00,
1,500 2026-10-01 12:47, 2,206 2026-10-02 01:31, 2,926 2026-10-02 15:54,
2,431 2026-10-02 05:34, 3,151 2026-10-02 19:56) and naming the vote and
effective blocks from `nodus/docs/DEPLOY_RUNBOOK.md` §2.2. The runbook now
requires a roadmap item with every future fork.

2026-10-06, HF-5 voted (operator: "tamam hf5 i aktive edelim", "evet gonder";
decision `docs/plans/decisions/2026-10-06-hf5-evm-activation.md`): param 14
`EVM_ACTIVE` voted in block 62,425, effective block 79,757, row identical on
7/7 (`nodus/docs/DEPLOY_RUNBOOK.md` §2.2). The roadmap's `history.evm.*` item
becomes the dated in-progress fork item "6 OCTOBER 2026 · HF-5" (key names kept;
it moves to "implemented" once block 79,757 is committed, dated by that block's
time); the Wiki fork list gains HF-5 ("voted, switches on at block 79,757") and
drops it from "Planned, not live"; Scan's hard-coded fork table
(`scan/app.js` `hardForks`) gains HF-5 / param 14 and its static "Planned hard
forks" list (`build-portals.mjs`) drops HF-5, so the live table shows it as
pending until the effective block.
