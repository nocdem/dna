// The NODUS send module — package (c3) of
// docs/plans/2026-09-25-web-wallet-nodus-send-design.md (§0a.3 "(c3)", §1.3):
// the nodus tier-2 client + the shared SPEND builder, compiled from C
// (crypto/nodus-send-wasm.c, scripts/build-nodus-send-wasm.sh) into
// ./send.wasm with its Emscripten glue ./send.js. This file adapts that
// module to the contract written at the top of ./client.js.
//
// NETWORK SETTINGS — `NODUS_SEND_NETWORK` below. The module accepts a server
// only if its ML-DSA-87 key is in `pins` (nodus_client_config_t
// pinned_server_fps, fail-closed, ML-KEM-1024 only), and a session only if
// the node reports `chainId` (dnac_supply chain_id32). These values belong to
// the wallet build (design §3 A3 / §5 items 6 and 17: "zincir kimliği ve
// checkpoint listesi derlemeye gömülür"; the site is the code's root of
// trust, §5 item 6). The testnet values are below (operator, 2026-09-30:
// open the wallet so it can be tested). With `null` instead,
// `nodusSendModuleFactory` is `null` and NODUS stays receive-only — no
// placeholder network is ever shipped.
//
//   {
//     chainId:   64 lowercase hex — the v3 chain id (32 bytes)
//     scheme:    'wss' (production: Caddy TLS on each node, design §1.1) or
//                'ws' (ONLY with every host 127.0.0.1: the localhost harness)
//     endpoints: [{ host: IPv4 dotted quad, port: 1..65535 }], 1..8
//                (nodus.h NODUS_CLIENT_MAX_SERVERS); tried in order
//     pins:      [128 lowercase hex] — SHA3-512 of each accepted server's
//                ML-DSA-87 public key; 1..64 (nodus-send-wasm.c NSW_MAX_PINS)
//   }
//
// Amounts and heights cross into C as decimal strings and come back as
// decimal strings (RT1 L4 F10); nothing here converts them to Number.
const HEX64 = /^[0-9a-f]{64}$/, HEX128 = /^[0-9a-f]{128}$/, RAW = /^(0|[1-9]\d{0,19})$/;
const OCTET = '(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)';
const IPV4 = new RegExp(`^${OCTET}(\\.${OCTET}){3}$`);
export const NODUS_SEND_MAX_ENDPOINTS = 8;   // nodus/include/nodus/nodus.h NODUS_CLIENT_MAX_SERVERS
export const NODUS_SEND_MAX_PINS = 64;       // crypto/nodus-send-wasm.c NSW_MAX_PINS
const MAX_COINS = 100;                       // nodus_types.h NODUS_DNAC_MAX_UTXO_RESULTS

// Nodus testnet (chain born 2026-09-30, the final pre-testnet genesis). The
// chain id was read from the live genesis document; each pin is the node's
// identity/nodus.fp, re-derived as SHA3-512(nodus.pk) on every node. Six
// nodes run the WebSocket entry (Caddy TLS on 443 with an IP certificate ->
// ws_port 4005, nodus/docs/DEPLOY_RUNBOOK.md §2.4); all seven validator keys
// are pinned.
export const NODUS_SEND_NETWORK = {
  chainId: 'a48d1a785500a1cdecd739ecd53ef0e95b1dc4a7a300f49176a7fa25ae176114',
  scheme: 'wss',
  // Tried in order (nodus_client). Each runs Caddy TLS on 443 -> the node's
  // WebSocket entry (runbook §2.4). EU-6 has none: its 443 serves the
  // websites and this wallet (nginx).
  endpoints: [
    { host: '164.68.116.180', port: 443 },   // EU-5
    { host: '154.38.182.161', port: 443 },   // US-1
    { host: '161.97.85.25', port: 443 },     // EU-1
    { host: '156.67.24.125', port: 443 },    // EU-2
    { host: '156.67.25.251', port: 443 },    // EU-3
    { host: '164.68.105.227', port: 443 },   // EU-4
  ],
  pins: [
    '03499d1fae35f9e9aaf60a1c3f18d8c7d1ffa49f2c65bd4b6a531bdf8ef92c21c90bf5e64f29fb0b9f689ac20e7dc9df418784c788ffc43c735c9b38253038e0', // US-1
    'fd429639366cbc41d98db7603d51166ed5542d2d161cf69ff1ab6dbe80176197dca892177f95cdb4757073531588bf63c7d3b91f6f016e0035272068de74b35c', // EU-1
    '16af3eaa620ab5d239ca63abd01943c7b1a8580a3c0204ec8a093bf7992c79df073b8ac0cacb4f01d6155fff97ef85a908dae4a044f70c1d523da1f43ce09dd7', // EU-2
    '04cdf00b3c37782b7df02fc0f71ba3b74893a60cbb800369d9ee6e97c46dd3edaf31ddf6cb29798c6e8e603d4c0dbb18e24f9d8f30c7adaeefad078f2225a659', // EU-3
    '681c12a60cae6956d1c7a1b8c75b08594961888e0d8319882fee4c94ce77b55fd7c1daee065caaacee6c28fb4f69226d1bca716a7be34e831604c88c4cbc6298', // EU-4
    'a7b23e52f02af2d2f526d58c741bb405825af8e31d753dc670b9c94cc01d2401fc7ecb8ddbdc1f33fe0bda0a365580e905d5f23c1be51d38c3d6055f5faa5ae6', // EU-5
    '6573f74c177c9d97ba784e9607b487125f973f71026931e522051d9ba6fe713a3dcadce98d4ad2e6eb854c56f6717918fbc1691b39b7adb15cc577b138213466', // EU-6
  ],
};

// GENESIS CLAIM DATA (0.1.26) — the allocation list the chain was born
// with, so the wallet can claim this wallet's allocation (nodus-cli
// `v2-claim` in the browser, crypto/nodus-send-wasm.c "GENESIS CLAIM"). No
// node RPC serves a manifest, a leaf list or a proof, so they belong to the
// wallet build next to the pinned chain id. The module trusts none of it:
// the manifest must decode strictly and re-hash to `manifestHash`, and the
// leaves must rebuild the snapshot root the manifest commits; otherwise
// claiming is refused (sending is unaffected).
//
//   {
//     manifest:     lowercase hex — the genesis manifest's canonical bytes
//                   (shared/dnac/manifest_wire.h "GenesisManifest v1")
//     manifestHash: 128 lowercase hex — dna_gman_hash of those bytes
//     leaves:       [{ sourceId: 2..256 lowercase hex (1..128 bytes),
//                      destBinding: 128 lowercase hex (SHA3-512 of the
//                      owner's ML-DSA-87 public key = its Nodus address),
//                      amount: raw decimal >= 1 }], 1..256
//                   (nodus-send-wasm.c NSW_CLAIM_MAX_LEAVES)
//   }
//
// Testnet values: the manifest bytes as stored in v2_manifests (read on two
// nodes, identical), its hash as the node stores it, and the single leaf of
// the genesis config the chain was born from — the Founder allocation,
// 50,000,000 NODUS (5,000,000,000,000,000 raw).
export const NODUS_CLAIM_MAX_LEAVES = 256;   // crypto/nodus-send-wasm.c NSW_CLAIM_MAX_LEAVES
const NODUS_CLAIM_MANIFEST_MAX = 8192;       // crypto/nodus-send-wasm.c NSW_CLAIM_MANIFEST_MAX
export const NODUS_CLAIM_DATA = {
  manifest: '00000001016345785d8a0000000200000000464bc4ea942d2a4de370068ad2759ecc8d9942345b6c21dc630bf986984c24a331055cdb8ca592acabcccad7ceff8b20cda772a0422c9240028e585f64a570d300000001382404d80cc70a0c8087e999e33f4640b218a2b3d4120b4bc6828d55dd7aafcb31826de220bd2ece2dfdca81d4e61891d1bd8469423db0f058d1c8ce4b2e4b6c010000000100000001004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e4e44532e47454e455349532e76310040de43bdfad6600bf5304afe6d6da4b55d20008704ecff4e32ccca43da78b8e7ca14164ad9f8a1a34d5f52ad193de0a49960e27148a53a5e0dd45a6363840c5a915e46f68b7108271d2f6b4d432ba4c9ab1098028068c1350e65480cd3453eb415fac7f92305d3af9a561e540421c6b6b3d99bad293f4c87a51f6e0c8fe9147a7d0000000000000001000000000000000100000000000000010100000000000000000011c37937e080000000000000000000ffffffffffffffff010101',
  manifestHash: '1807f972ba232b6822a0a2a622376a208b5730f10ad5099eb079d469713a17c2589b52fc069b6a67003de06ed78d027f17200377bb6136944594fe1ca431b4b8',
  leaves: [
    { // Founder
      sourceId: '0'.repeat(127) + '1',
      destBinding: '7a145ade5e99b16fbf04f23e590928a6cd21d1d38c39a8719924ec381b9d1b2123d999b4a7c6f459fe631f1595ae50a49c67918a870829b972eb2d95287ed2fd',
      amount: '5000000000000000',
    },
  ],
};

// A checked, frozen copy of claim data; throws on anything outside the
// shape documented above (the cryptographic checks are the module's).
export function validateNodusClaimData(data) {
  const bad = what => new Error(`Nodus claim data: ${what}.`);
  if (!data || typeof data !== 'object') throw bad('missing');
  const { manifest, manifestHash, leaves } = data;
  if (typeof manifest !== 'string' || !/^([0-9a-f]{2})+$/.test(manifest) || manifest.length > 2 * NODUS_CLAIM_MANIFEST_MAX) throw bad('manifest must be lowercase hex');
  if (typeof manifestHash !== 'string' || !HEX128.test(manifestHash)) throw bad('manifestHash must be 128 lowercase hex characters');
  if (!Array.isArray(leaves) || leaves.length < 1 || leaves.length > NODUS_CLAIM_MAX_LEAVES) throw bad(`1 to ${NODUS_CLAIM_MAX_LEAVES} leaves are required`);
  const list = leaves.map(leaf => {
    if (!leaf || typeof leaf.sourceId !== 'string' || !/^([0-9a-f]{2}){1,128}$/.test(leaf.sourceId) ||
        typeof leaf.destBinding !== 'string' || !HEX128.test(leaf.destBinding) ||
        typeof leaf.amount !== 'string' || !RAW.test(leaf.amount) || leaf.amount === '0' || BigInt(leaf.amount) >= 2n ** 64n) throw bad('a leaf is not { sourceId, destBinding, amount }');
    return Object.freeze({ sourceId: leaf.sourceId, destBinding: leaf.destBinding, amount: leaf.amount });
  });
  return Object.freeze({ manifest, manifestHash, leaves: Object.freeze(list) });
}

// A checked, frozen copy of a network settings object; throws on anything
// outside the shape documented above.
export function validateNodusSendNetwork(network) {
  const bad = what => new Error(`Nodus network settings: ${what}.`);
  if (!network || typeof network !== 'object') throw bad('missing');
  const { chainId, scheme, endpoints, pins } = network;
  if (typeof chainId !== 'string' || !HEX64.test(chainId)) throw bad('chainId must be 64 lowercase hex characters');
  if (scheme !== 'wss' && scheme !== 'ws') throw bad("scheme must be 'wss' or 'ws'");
  if (!Array.isArray(endpoints) || endpoints.length < 1 || endpoints.length > NODUS_SEND_MAX_ENDPOINTS) throw bad(`1 to ${NODUS_SEND_MAX_ENDPOINTS} endpoints are required`);
  const list = endpoints.map(endpoint => {
    if (!endpoint || typeof endpoint.host !== 'string' || !IPV4.test(endpoint.host) || !Number.isInteger(endpoint.port) || endpoint.port < 1 || endpoint.port > 65535) throw bad('an endpoint is not { host: IPv4, port }');
    return Object.freeze({ host: endpoint.host, port: endpoint.port });
  });
  // Plain ws:// carries the tier-2 session without TLS; the pinned PQ
  // handshake still protects it, but it is kept to the local harness.
  if (scheme === 'ws' && !list.every(endpoint => endpoint.host === '127.0.0.1')) throw bad("scheme 'ws' is allowed only for 127.0.0.1");
  if (!Array.isArray(pins) || pins.length < 1 || pins.length > NODUS_SEND_MAX_PINS || !pins.every(pin => typeof pin === 'string' && HEX128.test(pin)) || new Set(pins).size !== pins.length) throw bad(`1 to ${NODUS_SEND_MAX_PINS} distinct pins of 128 lowercase hex characters are required`);
  return Object.freeze({ chainId, scheme, endpoints: Object.freeze(list), pins: Object.freeze([...pins]) });
}

function raw(value, what) {
  if (typeof value !== 'string' || !RAW.test(value)) throw new Error(`Invalid ${what}.`);
  return value;
}

// Instantiates the module and returns the object ./client.js expects.
// `loadGlue` exists for tests (a node build of the same C, see
// test/nodus-send-wasm.test.js); the wallet always uses ./send.js.
export async function createNodusSendModule(network, { claim = null, loadGlue = () => import('./send.js') } = {}) {
  const net = validateNodusSendNetwork(network);
  // Claim data refused by the shape check or by the module leaves claiming
  // off (claimError) and changes nothing else.
  let claimData = null, claimError = claim ? null : 'Claiming is not available in this wallet build.';
  if (claim) { try { claimData = validateNodusClaimData(claim); } catch (error) { claimError = error.message; } }
  const { default: createNodusSendWasm } = await loadGlue();
  // SOCKFS opens `${scheme}://<ip>:<port>/` with subprotocol "binary" (the
  // nodus WS entry echoes it, nodus_ws.c). Emscripten reads Module.websocket
  // (settings.js INCOMING_MODULE_JS_API 'websocket'; libsockfs.js url /
  // subprotocol).
  const M = await createNodusSendWasm({ websocket: { url: `${net.scheme}://`, subprotocol: 'binary' } });
  const num = (name, types = [], args = []) => M.ccall(name, 'number', types, args);
  const str = (name, types = [], args = []) => M.ccall(name, 'string', types, args);
  const call = (name, types = [], args = []) => M.ccall(name, 'number', types, args, { async: true });
  const failure = () => new Error(str('nsw_error') || 'The Nodus send module failed.');
  const check = rc => { if (rc !== 0) throw failure(); };

  check(num('nsw_net_reset'));
  check(num('nsw_net_set_chain', ['string'], [net.chainId]));
  for (const endpoint of net.endpoints) check(num('nsw_net_add_endpoint', ['string', 'number'], [endpoint.host, endpoint.port]));
  for (const pin of net.pins) check(num('nsw_net_add_pin', ['string'], [pin]));
  if (claimData) {
    try {
      check(num('nsw_claim_reset'));
      check(num('nsw_claim_set_manifest', ['string', 'string'], [claimData.manifest, claimData.manifestHash]));
      for (const leaf of claimData.leaves) check(num('nsw_claim_add_leaf', ['string', 'string', 'string'], [leaf.sourceId, leaf.destBinding, leaf.amount]));
      check(num('nsw_claim_seal'));
    } catch (error) { claimError = error.message; }
  }
  const claimReady = () => { if (claimError) throw new Error(claimError); };
  const WINDOW = ['open', 'not-open', 'closed'], CLAIMED = ['no-evidence', 'yes', 'unknown'];

  return {
    async unlock({ seed } = {}) {
      if (!(seed instanceof Uint8Array) || seed.length !== 32) throw new Error('Nodus signing seed must be 32 bytes.');
      // The C side wipes this copy on every path (nsw_unlock); the caller
      // wipes its own (./client.js unlock).
      M.HEAPU8.set(seed, num('nsw_seed_buf'));
      check(await call('nsw_unlock'));
      return { fingerprint: str('nsw_fingerprint'), chainId: str('nsw_chain_hex') };
    },
    async balance() {
      check(await call('nsw_balance'));
      return { total: str('nsw_bal_total'), spendable: str('nsw_bal_spendable') };
    },
    async list() {
      check(await call('nsw_list'));
      const coins = [];
      for (let i = 0, n = num('nsw_list_count'); i < n; i++) {
        coins.push({ nullifier: str('nsw_list_nul', ['number'], [i]), amount: str('nsw_list_amount', ['number'], [i]) });
      }
      return { tip: str('nsw_list_tip'), coins, truncated: num('nsw_list_truncated') === 1 };
    },
    async buildAndSign({ to, amount, expiryHeight, coins } = {}) {
      if (typeof to !== 'string' || !HEX128.test(to)) throw new Error('Enter a Nodus address: 128 characters, 0-9 and a-f.');
      raw(amount, 'amount'); raw(expiryHeight, 'validity height');
      if (!Array.isArray(coins) || coins.length > MAX_COINS) throw new Error('Invalid coin list.');
      num('nsw_req_reset');
      for (const coin of coins) {
        if (!coin || typeof coin.nullifier !== 'string' || !HEX128.test(coin.nullifier)) throw new Error('Invalid coin list.');
        check(num('nsw_req_add_coin', ['string', 'string'], [coin.nullifier, raw(coin.amount, 'coin amount')]));
      }
      check(await call('nsw_build_and_sign', ['string', 'string', 'string'], [to, amount, expiryHeight]));
      const at = num('nsw_built_env'), length = num('nsw_built_env_len');
      const inputs = [];
      for (let i = 0, n = num('nsw_built_n_in'); i < n; i++) inputs.push(str('nsw_built_in', ['number'], [i]));
      return {
        envelope: M.HEAPU8.slice(at, at + length),
        intentId: str('nsw_built_intent'),
        // Read back from the envelope bytes by the C side (nodus_v2_spend_build's
        // decode, checked in nsw_build_core) — never echoed from the request.
        decoded: {
          recipient: str('nsw_built_recipient'), amount: str('nsw_built_amount'), fee: str('nsw_built_fee'),
          change: str('nsw_built_change'), expiryHeight: str('nsw_built_expiry'), chainId: str('nsw_built_chain'), inputs
        }
      };
    },
    async submit({ envelope } = {}) {
      if (!(envelope instanceof Uint8Array) || envelope.length === 0) throw new Error('Invalid transfer.');
      const at = num('nsw_req_env_alloc', ['number'], [envelope.length]);
      if (!at) throw new Error('Out of memory.');
      M.HEAPU8.set(envelope, at);
      const rc = await call('nsw_submit');
      if (rc === 0) return { accepted: true };
      if (rc === 1) return { accepted: false, message: str('nsw_error') };
      throw failure();
    },
    async scanConfirm({ intentId, fromHeight, toHeight } = {}) {
      if (typeof intentId !== 'string' || !HEX128.test(intentId)) throw new Error('Invalid transfer id.');
      check(await call('nsw_scan', ['string', 'string', 'string'], [intentId, raw(fromHeight, 'block height'), raw(toHeight, 'block height')]));
      const tip = str('nsw_scan_tip');
      return num('nsw_scan_found') === 1 ? { tip, found: true, height: str('nsw_scan_height') } : { tip, found: false };
    },
    async tick() {
      check(await call('nsw_tick'));
    },
    // GENESIS CLAIM. claimStatus() -> { found: false } or { found: true,
    // amount (raw), tip, startHeight, endHeight, window: 'open' | 'not-open'
    // | 'closed' (for the next block), claimed: 'yes' (proven: the node's
    // unclaimed total is below this allocation) | 'no-evidence' | 'unknown'
    // (older node), outputId: the coin id a claim of it creates — its
    // tracking id }. See nodus-send-wasm.c nsw_claim_status.
    async claimStatus() {
      claimReady();
      check(await call('nsw_claim_status'));
      if (num('nsw_claim_found') !== 1) return { found: false };
      return {
        found: true, amount: str('nsw_claim_amount'), tip: str('nsw_claim_tip'), startHeight: str('nsw_claim_start'),
        endHeight: str('nsw_claim_end'), window: WINDOW[num('nsw_claim_window')], claimed: CLAIMED[num('nsw_claim_claimed')],
        outputId: str('nsw_claim_output')
      };
    },
    // claimBuild() -> { bytes: Uint8Array, claimId: SHA3-512 of the bytes,
    // decoded: { recipient, amount, chainId, nullifier, outputId, leafIndex } }
    // — `decoded` is read back FROM THE SIGNED BYTES by the C side.
    async claimBuild() {
      claimReady();
      check(await call('nsw_claim_build'));
      const at = num('nsw_claim_built_bytes'), length = num('nsw_claim_built_len');
      return {
        bytes: M.HEAPU8.slice(at, at + length), claimId: str('nsw_claim_built_id'),
        decoded: {
          recipient: str('nsw_claim_built_recipient'), amount: str('nsw_claim_built_amount'), chainId: str('nsw_claim_built_chain'),
          nullifier: str('nsw_claim_built_nullifier'), outputId: str('nsw_claim_built_output'), leafIndex: str('nsw_claim_built_leaf')
        }
      };
    },
    // claimSubmit({ bytes }) -> { accepted: boolean, message?: string }; only
    // the bytes of the last claimBuild() are sent (compared in C).
    async claimSubmit({ bytes } = {}) {
      claimReady();
      if (!(bytes instanceof Uint8Array) || bytes.length === 0) throw new Error('Invalid claim.');
      const at = num('nsw_req_env_alloc', ['number'], [bytes.length]);
      if (!at) throw new Error('Out of memory.');
      M.HEAPU8.set(bytes, at);
      const rc = await call('nsw_claim_submit');
      if (rc === 0) return { accepted: true };
      if (rc === 1) return { accepted: false, message: str('nsw_error') };
      throw failure();
    },
    // Synchronous: none of these reaches emscripten_sleep (nodus-send-wasm.c
    // nsw_cancel / nsw_lock), so they are safe while another export waits.
    cancel() { M.ccall('nsw_cancel', null, [], []); },
    lock() { M.ccall('nsw_lock', null, [], []); },
    // Sets Emscripten's ABORT: a pending wake-up of a suspended export then
    // returns without resuming compiled code (libasync.js handleSleep,
    // `if (ABORT) return`). abort() throws by design; that throw is the
    // expected outcome here.
    release() { try { M.abort('Nodus send module released'); } catch { /* aborted */ } },
    memory: { get buffer() { return M.HEAPU8.buffer; } }
  };
}

// Registration point read by src/app.js: null while the network settings
// above are null (NODUS stays receive-only, src/nodus/network.js).
export const nodusSendModuleFactory = NODUS_SEND_NETWORK ? () => createNodusSendModule(NODUS_SEND_NETWORK, { claim: NODUS_CLAIM_DATA }) : null;
