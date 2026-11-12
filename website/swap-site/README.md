# swap.nodusnetwork.io page

Source of the page installed on EU-6 at /var/www/swap.nodusnetwork.io/public (see ../deploy/README.md).
The public root also holds assets/nodus-mark.svg and assets/fonts/inter-latin{,-ext}.woff2, copied from ../assets.
Static: no framework, no dependency, no build step for the source. The deploy copy of the page files comes from `stamp.mjs` (see Deploy below), not from copying the files below as they are.
The bot is reached directly at `https://62.171.136.77` under `/amm/` (`BOT_ORIGIN` in `bot.js`; plan section 18 change 5;
givens item 100). EU-6 serves the page only and forwards nothing to the bot; the web server in front of the bot is
`../deploy/amm-https.conf`. Nothing between the page and the bot is signed or checked (givens item 69).

Plan: `docs/plans/2026-11-08-swap-bot-plan.nodus1.md` sections 5-8, 14, 18 (changes 2, 3), 19.

| File | Holds |
| --- | --- |
| `index.html`, `swap.css` | The page and its look (CSP: no inline script or style). |
| `swap.js` | DOM wiring only. |
| `flow.js` | The order of the steps: status, press (only once the extension is connected), yes, bounded polling; liquidity add and withdraw. No DOM. |
| `swap-logic.js` | Units, the minimum to receive, request bodies, signed texts, typed data, refusal words, swap states. |
| `bot.js` | Fetch client of the bot's routes (`amm_http.h`). |
| `extension.js` | The extension's EXISTING site methods (`nodus_requestAccounts`, `eth_requestAccounts`, `nodus_signMessage`). |
| `log.js` | The page's diagnostic log: one browser-console line per event, `[swap-site] <ISO time> <area> <event> name=value ... ms=<duration>` (`console.info`, `console.warn` for failures). Written by `swap.js` (page load, clicks, busy on/off, typing once the user pauses), `bot.js` (every request: method, path, status, answer's reason / state / request number / amount / number / fee / validUntil, duration), `extension.js` (extension found or not, connect asked / accounts / refused), `flow.js` (status, press, confirm, adapter call and each announced step, follow reads, withdraw, liquidity). Named plain fields only: no error object or stack, no request body; a field whose name contains signature, publickey, privatekey, secret, seed, mnemonic or words (any case) is replaced by "[omitted]" (`HIDDEN` in `log.js`). A logger never throws into its caller. |
| `adapter.js` | The ONE module that calls the extension's NEW site methods. Its method names and parameter shapes are constants (`EXTENSION_CALLS`) that main fills in; until then every call refuses with `not_configured` and sends nothing. |
| `swap.js` page lines | "Pool" (both tabs) shows the status reserves as "<USDT> USDT · <NODUS> NODUS", "Empty: no liquidity yet" or "Too large to show", from the status read at page open (`poolText`). "Price movement" (swap tab, after the bot's answer) is how far the bot's rate for the asked amount is below the pool price from the same reserves (`priceMovementPercent`), "—" when the pool price is unknown; reset like the other answer fields. "Your payment is counted after" follows the typed amount and the direction (`waitText`: 3 / 5 / 33 Ethereum blocks by USDT amount, the bot's default tiers, constants because `/amm/status` does not carry them; "its Nodus block is committed" for NODUS to USDT). After each swap answer and each pair answer the page re-reads `/amm/status` (the existing GET; a failed re-read changes nothing) and refreshes the Pool lines and the pool price. No new request kind, no price estimate while typing. |
| `swap.js` approval texts | While the extension is asked, the message line names the window the user waits for (`stepText` in `flow.js`, steps announced by the adapter's optional `{ onStep }` just before each extension call; nothing about the calls changes). NODUS to USDT: "Step 1 of 2" holding the NODUS payment, "Step 2 of 2" the Nodus signature, then the extension posts to the bot and sends the payment (the page cannot see that part and says so). USDT to NODUS: one call with two windows (signed request, USDT payment), no step numbers. Liquidity add: hold "Step 1 of 2", then "Step 2 of 2" three windows (Ethereum signature, Nodus signature, USDT payment). Every text says the window can be behind the browser window and to click the Nodus extension icon. While the sequence runs the approve buttons, the ask buttons, the amount, direction, tolerance and its chips are disabled (`setBusy`); the tolerance field used to re-enable the approve button. The follow lasts 240 reads x 5 s = 20 minutes (the bot's USDT payout is final after 3 Ethereum blocks, about 36 seconds), then "Check again". `payout_pending` (`describeSwapState`): NODUS to USDT shows the answer's `paid` amount when it is a digit string and the 3-block wait (`PAYOUT_FINAL_DEPTH_ETH`, the bot's `payout_final_depth_eth`, about 36 seconds; not mined-claims, the answer carries no hash); USDT to NODUS says the NODUS payout is marked finished when confirmed in a Nodus block, with no number (the bot sets none, `amm_nodus_pay.c` finish_confirmed). |
| `package.json` | `{"type":"module"}` only, so `node --test` loads the `.js` files as modules. Not needed on the server. |
| `test/` | `node --test website/swap-site/test/*.test.js` (Node 20 or later; Node 22 does not accept the bare directory): no browser, no network. |

| `stamp.mjs` | The deploy step: writes the deployable copy with a content version on every script and on the stylesheet (see Deploy). |

Deploy:
1. Run `node website/swap-site/stamp.mjs <outDir>` (an empty or new directory). It writes `index.html`, `swap.css` and every module `swap.js` reaches through its imports, each module import and the two references in `index.html` carrying `?v=<first 12 hex of the sha256 of the referenced output file>`, and prints one line per file: name, version, sha256. `package.json`, `README.md`, `test/` and modules the page does not reach are not written; the source is not changed.
2. Upload the files in `<outDir>`, plus the unchanged `assets/`, to the public root.
3. Compare the printed sha256 values with the files on the server and at the public address.

Why: the public edge caches the page's scripts for 4 hours (`cache-control: public, max-age=14400, must-revalidate`) while the page itself revalidates, so without a version a browser can run an older cached script under a new page (measured 2026-11-12). A changed module changes its own version and the version of every module that imports it, up to the `swap.js` reference in `index.html`. This is the same rule as `website/build-portals.mjs`.

Recorded residual: a signed liquidity withdrawal whose answer did not arrive is kept in the page's memory only and resent unchanged by the same button. After a page reload it is no longer held by the page, and the bot has no withdrawal status route, so the page cannot look it up.
