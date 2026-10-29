# Extension packaging

The approved plan is `/opt/dna/docs/plans/approved/2026-10-28-nodus-extension.md`,
section 9. The extension uses the installed Vite 7.3.7 and the wallet config's
version definition and third-party license helpers. No package script or
dependency is added.

The orchestrator first builds and verifies the WASM inputs using the wallet's
existing scripts and parity gates:

| Input | Existing builder |
| --- | --- |
| `src/nodus/send.js` and `src/nodus/send.wasm` | `scripts/build-nodus-send-wasm.sh` |
| `src/nodus/mldsa87.wasm` | `scripts/build-nodus-wasm.sh` |
| `src/cpunk/legacy-dilithium.wasm` | `scripts/build-cpunk-wasm.sh` |

Then, from `web-wallet/`:

```sh
bash scripts/build-extension.sh
CHROMIUM_PATH=/usr/bin/chromium node --test extension/test/package-smoke.test.js
node --test extension/test/manifest.test.js
```

The build writes `dist-extension/unpacked/` and one
`dist-extension/nodus-wallet-<manifest version>.zip`. It prints **every archived
file and its uncompressed byte size**, sorted by path. The smoke test also prints
every extracted file's size. Neither an actual archive inventory nor a successful
Chromium load is established until these commands run; syntax checking alone
does not verify packaging. The packaging script does not rebuild WASM.

The source manifest retains its SVG source paths. The emitted manifest rewrites
both icon maps to PNGs rendered from that exact source by `/usr/bin/rsvg-convert`
at every declared size: 16, 19, 32, 38, 48, 64, 128 and 512 pixels. The current
[Chrome icon documentation](https://developer.chrome.com/docs/extensions/reference/manifest/icons)
allows supported raster formats and excludes SVG. No pinned copy was found in
`/home/nocdem/refs` by filename and Chrome URL/SVG-icon text searches; the config
labels the conclusion relative to that pinned set as inference.

The manifest's `content_scripts[].js`, `run_at: document_start`, `all_frames`
and `world: MAIN` entries are retained. Chrome's
[content-script manifest schema](https://developer.chrome.com/docs/extensions/reference/manifest/content-scripts) (web page, not pinned; inference)
provides file, timing and execution-world fields without a module type. Each
entry therefore gets a separate IIFE with dynamic imports inlined and no shared
imports. The worker also remains classic: its source lazy import is inlined,
because Chrome's [worker documentation](https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/basics#import-scripts) (web page, not pinned; pinned support: refs/metamask-extension-v13.54.0/development/webpack/README.md:237)
excludes dynamic `import()`. `process.env.IN_TEST` is replaced with constant
`false` in all builds. The stream dependencies use the installed browser
implementations of buffer, events and process; the stream 3 process import is
module-local, following the pinned MetaMask config's `ProvidePlugin` at
`development/webpack/webpack.config.ts:220-225`.

Only the three listed WASM binaries are copied, unchanged, to `wasm/`; their
loaders receive `chrome.runtime.getURL()` paths during bundling. Vite copies
`public/` (the existing logo, two Inter font files and font license) and emits
the coin images and shared page code/styles reached by the three HTML entries.
The extension source tree, tests and `site-sdk/` are not copied. The license
collector includes modules with `renderedLength > 0` across all four builds,
using the same native notices and appendix texts as the wallet build.

The smoke test skips only when the versioned zip is absent, with a message
naming the build command. A present but invalid zip, unavailable Chromium,
startup failure or missing UI/provider fails. It checks PNG signatures and
dimensions, classic-script syntax, copied bytes, worker execution, fresh-profile
create/import UI, and EIP-6963 name `Nodus Wallet` / reverse domain
`io.nodusnetwork.wallet`. A local `eth_chainId` read checks the content bridge.
The local server also acts as a rejecting proxy and Playwright aborts external
requests. No wallet is unlocked and no chain is called. Temporary extraction,
profile and server are cleaned up in `finally`.

Coverage limit: the smoke test checks loading and local discovery, not WASM
instantiation, signing, sending or browser-family interoperability. An old zip
can contain stale bundled JavaScript, so rebuild immediately before the test;
copied WASM and public assets are compared to current input bytes.
