# swap.nodusnetwork.io page

Source of the page installed on EU-6 at /var/www/swap.nodusnetwork.io/public (see ../deploy/README.md).
The public root also holds assets/nodus-mark.svg and assets/fonts/inter-latin{,-ext}.woff2, copied from ../assets.
Static: no framework, no dependency, no build step. Every file below is copied to the public root.
The bot is reached directly at `https://62.171.136.77` under `/amm/` (`BOT_ORIGIN` in `bot.js`; plan section 18 change 5;
givens item 100). EU-6 serves the page only and forwards nothing to the bot; the web server in front of the bot is
`../deploy/amm-https.conf`. Nothing between the page and the bot is signed or checked (givens item 69).

Plan: `docs/plans/2026-11-08-swap-bot-plan.nodus1.md` sections 5-8, 14, 18 (changes 2, 3), 19.

| File | Holds |
| --- | --- |
| `index.html`, `swap.css` | The page and its look (CSP: no inline script or style). |
| `swap.js` | DOM wiring only. |
| `flow.js` | The order of the steps: status, press, yes, bounded polling; liquidity add and withdraw. No DOM. |
| `swap-logic.js` | Units, the minimum to receive, request bodies, signed texts, typed data, refusal words, swap states. |
| `bot.js` | Fetch client of the bot's routes (`amm_http.h`). |
| `extension.js` | The extension's EXISTING site methods (`nodus_requestAccounts`, `eth_requestAccounts`, `nodus_signMessage`). |
| `adapter.js` | The ONE module that calls the extension's NEW site methods. Its method names and parameter shapes are constants (`EXTENSION_CALLS`) that main fills in; until then every call refuses with `not_configured` and sends nothing. |
| `package.json` | `{"type":"module"}` only, so `node --test` loads the `.js` files as modules. Not needed on the server. |
| `test/` | `node --test website/swap-site/test/` (Node 20 or later): no browser, no network. |

Recorded residual: a signed liquidity withdrawal whose answer did not arrive is kept in the page's memory only and resent unchanged by the same button. After a page reload it is no longer held by the page, and the bot has no withdrawal status route, so the page cannot look it up.
