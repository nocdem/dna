# Connect with Nodus

Copy this directory as a unit. `index.mjs` is a dependency-free JavaScript
module; keep `nodus-site-verify.mjs` and `nodus-site-verify.wasm` beside it.
The same files work in a browser and in Node. Provider calls require the
Nodus Wallet browser extension; verification does not.

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
`nodus_requestAccounts` and returns the first account object. Discovery waits
for a matching announcement. The extension's identity is `name: "Nodus Wallet"`,
`rdns: "io.nodusnetwork.wallet"` (`extension/src/inpage.js`, `startInpage`).
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

