# Connect with Nodus

Copy this directory as a unit. `index.mjs` is a dependency-free JavaScript
module; keep `nodus-site-verify.mjs` and `nodus-site-verify.wasm` beside it.
The same files work in a browser and in Node. Provider calls require the
Nodus Connect browser extension; verification does not.

## Include in a site

```html
<script type="module">
  import { createConnectButton, signMessage } from './site-sdk/index.mjs';

  const button = createConnectButton({
    onConnect(account) {
      // account = { address: <128 hex>, publicKey: "0x" + <5184 hex> }
      console.log(account.address);
    },
    onError(error) { console.error(error.message); },
  });
  document.body.append(button);

  // Call from your application's message approval action:
  // const signature = await signMessage(textOrUint8Array);
</script>
```

Without the optional button:

```js
import { connect, signMessage } from './site-sdk/index.mjs';

const account = await connect();
// The server issues a fresh random, single-use challenge for this sign-in.
const challengeResponse = await fetch('/auth/nodus/challenge', { method: 'POST' });
if (!challengeResponse.ok) throw new Error('Could not request a sign-in challenge.');
const { message } = await challengeResponse.json();
const signature = await signMessage(message);
const signInResponse = await fetch('/auth/nodus/sign-in', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ ...account, message, signature }),
});
if (!signInResponse.ok) throw new Error('Sign-in was refused.');
```

`connect()` discovers the provider through `eip6963:announceProvider`,
requests reannouncement with `eip6963:requestProvider`, then calls
`nodus_requestAccounts` and returns the first account object: `address`,
`publicKey` and, when the wallet has confirmed one for that address, the
account's chain name `name` (3 to 36 of a-z and 0-9; the field is absent
otherwise). Chain names are public on chain. Discovery waits
for a matching announcement. The browser extension is named Nodus Connect.
For compatibility, its provider discovery retains the legacy identity
`name: "Nodus Wallet"`, `rdns: "io.nodusnetwork.wallet"`
(`extension/src/inpage.js`, `startInpage`). This module matches both values
exactly; the product rename does not change them.
The module does not select another wallet from a global provider variable.

`signMessage(message)` connects first if needed, then calls
`nodus_signMessage` with `[hexEncodedMessage, account.address]`. It returns the
signature hex string after wallet approval. Strings mean UTF-8 text, including
strings such as `"abc"` or `"0x1234"`; a `Uint8Array` means exact bytes.
Empty strings and empty byte arrays reject before any provider request.
The extension accepts at most 65,536 decoded message bytes. Provider errors
propagate to the caller.

`createConnectButton({ document, onConnect, onError })` returns a plain
`button` with `type="button"` and label **Connect with Nodus**. Append it where
your page needs it. It connects on click and passes the account to `onConnect`.
`createNodusConnector({ window })` creates an independent connector, for example
for an explicitly supplied browser window.

## Swap and liquidity add (swap.nodusnetwork.io)

Four calls send one request object to the Nodus provider: `holdTransfer`,
`sendNodusToUsdt`, `sendUsdtToNodus` and `sendLiquidityAdd`. The extension that
pays signs the user's request, posts it to the bot itself at `botUrl` (an https
address without a path; the site gives it with each request) and pays only if
that request reached the bot (the bot answered over HTTP with `"received": true`).
If it did not, nothing is paid and the call rejects with `error.data`
`{ delivered: false, paid: false, answered, reason }` (`answered` is true when the bot
replied over HTTP; `reason` is the bot's refusal word or `unreachable` / `http_<status>`).
When the bot refuses because an open approval with the same sender and amount exists
(`reason: "open_approval"`), `error.data.openRequestNumber` is that open swap's request
number (a decimal string, 1 to 4294967295) for the site to show it; any other form is
dropped. The data object also carries the `cause` field the JSON-RPC error library adds
(`null` when absent). After a delivered request that was not paid the data is
`{ delivered: true, paid: false | "unknown", cause: null }`. `paid` is `"unknown"` whenever the
payment's broadcast step was reached (its pending record was saved) and then failed, whatever the
error or the wallet state afterwards: the transaction may have been sent, so check the wallet's
Activity before trying again. `paid: false` means the failure came before that step. For a
liquidity add `nodusSent` is `"unknown"` in the same way. Only one `holdTransfer` can be in
progress at a time; a second call is refused with "A hold is already being made". A new hold of a
site replaces its earlier hold only when the new one is stored.

- `holdTransfer({ account, to, amount })`: builds and signs a native NODUS
  transfer of `amount` NODUS units to `to` (128 hex) from the connected
  `account` and keeps it unsent. Resolves `{ holdId, transferId, chainId,
  expiryHeight }`; `transferId` and `chainId` go into the request text.
- `sendNodusToUsdt({ holdId, botUrl, text })`: signs `text` (the NODUS to USDT
  request text of the swap plan, section 6.4.4, naming the held transfer),
  posts it, then sends the held transfer. A held transfer past its expiry is
  never sent.
- `sendUsdtToNodus({ from, botUrl, token, payTo, destination, amount,
  minimumToReceive, requestNumber })`: signs the typed request (domain chain id
  = the extension's selected Ethereum network), posts it, then pays `amount`
  USDT units of `token` to `payTo`.
- `sendLiquidityAdd({ holdId, botUrl, ethereumAddress, token, payTo,
  usdtAmount, nodusAmount, requestNumber, text })`: signs both halves, posts the
  flat add body, then sends both payments.

`token` must be the USDT contract the extension knows for the selected network
(Ethereum: `0xdAC17F958D2ee523a2206206994597C13D831ec7`, compared as an address, so letter
case does not matter). Any other token is refused with error -32602 before anything is
signed, posted or paid, because the bot counts only its own USDT contract. On Ethereum
Sepolia every token is refused until the test USDT address is set in the extension. The
bot's answer is read with a 65,536-byte limit; a larger answer counts as not delivered.

The Ethereum network is switched first with `wallet_switchEthereumChain`
(`0xaa36a7` for Ethereum Sepolia), which is not part of this module.

## Verify on a Node server

Use the same downloaded files, without the extension or a browser. For example,
the two routes above can call these functions with the browser session's ID
from your server's session handling, never an ID supplied in the request body:

```js
import { randomUUID } from 'node:crypto';
import { addressOf, verify } from './site-sdk/index.mjs';

const challenges = new Map();
const siteOrigin = process.env.SITE_ORIGIN; // Your configured browser origin.
if (!siteOrigin) throw new Error('SITE_ORIGIN is required.');

// POST /auth/nodus/challenge: return this object as JSON.
export function issueChallenge(sessionId) {
  const message = randomUUID();
  challenges.set(sessionId, message);
  return { message };
}

// POST /auth/nodus/sign-in: submitted is the parsed JSON request body.
// Establish a signed-in session only when this returns true.
export async function checkSignIn(sessionId, submitted) {
  const message = challenges.get(sessionId);
  challenges.delete(sessionId); // Consume once, before any asynchronous work.
  if (!message || submitted.message !== message) return false;
  if (submitted.address !== await addressOf(submitted.publicKey)) return false;
  return verify({
    origin: siteOrigin,
    message, // The server-issued challenge, checked against the submission.
    publicKey: submitted.publicKey,
    signature: submitted.signature,
  });
}
```

Every sign-in needs a new server-issued random challenge. Store it for the
requesting browser session and consume it once; a previously signed challenge
must not authenticate another attempt. The example's map consumes it before
verification; if your application uses shared session storage, make that
read-and-consume operation atomic there too. A rejected promise also refuses
sign-in.

Before trusting the submitted address, the server checks that it equals
`await addressOf(submitted.publicKey)`: SHA3-512 of the public key, encoded as
128 lowercase hex characters without a prefix. This is the Nodus address rule
in `web-wallet/src/nodus/derive.js`. The helper hashes through WebAssembly's
`qgp_sha3_512`; JavaScript only converts the result to hex. `addressOf(publicKey)`
accepts the same public-key formats as `verify()` and returns a promise of the
address; malformed public keys reject with `TypeError`.

Supply the site's expected origin from server configuration. Verification uses
its bytes as given, without normalization: scheme, host, and any serialized
port, with no path or trailing slash. Pass the original message bytes or the
same UTF-8 text. `publicKey` (2,592 bytes) and `signature` (4,627 bytes) accept
`Uint8Array` or hex strings, with an optional `0x` prefix. `verify()` returns a
promise of `true` or `false`; malformed inputs return `false`. Failures to load
the WebAssembly artifact or allocate its input reject the promise.

Verification runs `nodus_verify_site_message` from
`nodus/src/crypto/nodus_sign.c`, using the project's `qgp_sha3_512` and
ML-DSA-87 verifier. JavaScript only encodes inputs and calls WebAssembly.
There is no signing, identity or key-generation interface in this module.

The approved construction is:

```text
digest = SHA3-512(origin_len_be(4) || origin || message)
signed bytes = "NDS1" || 0x0C || 00 00 00 40 || digest   (73 bytes)
```

The extension signs its connection-bound origin. This follows
`docs/plans/decisions/2026-10-28-extension-nodus-site-signing.md`, including
the approved origin-layout addendum. A signature for another origin or the
earlier no-origin construction fails verification.

## Build the verifier

`bash web-wallet/scripts/build-nodus-site-verify-wasm.sh` builds only the two
verifier artifacts in this directory. It requires Emscripten **6.0.10** and
the existing OpenSSL WebAssembly archive. Set `EMCC_BIN` (or `EMSDK`) and
`OPENSSL_WASM_PREFIX` to their local locations as needed. It does not build
the wallet's send module.

