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
// identity/nodus.fp, re-derived as SHA3-512(nodus.pk) on every node. Only
// EU-5 runs the WebSocket entry today (Caddy TLS on 443 with an IP
// certificate -> ws_port 4005, nodus/docs/DEPLOY_RUNBOOK.md §2.4); every
// validator key is pinned so the other nodes can be added as endpoints later.
export const NODUS_SEND_NETWORK = {
  chainId: 'a48d1a785500a1cdecd739ecd53ef0e95b1dc4a7a300f49176a7fa25ae176114',
  scheme: 'wss',
  endpoints: [{ host: '164.68.116.180', port: 443 }],   // EU-5
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
export async function createNodusSendModule(network, { loadGlue = () => import('./send.js') } = {}) {
  const net = validateNodusSendNetwork(network);
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
export const nodusSendModuleFactory = NODUS_SEND_NETWORK ? () => createNodusSendModule(NODUS_SEND_NETWORK) : null;
