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
//                (nodus.h NODUS_CLIENT_MAX_SERVERS); tried round-robin from
//                a random start (rotateNodusEndpoints below)
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
const ADDR_HISTORY_MAX_LIMIT = 100;          // nodus/include/nodus/nodus.h NODUS_DNAC_ADDR_HISTORY_MAX_LIMIT
// The staking ops and their SYSTEM runtime_op (nodus_witness_runtime.h
// DNA_SYSRULE_STAKE / _DELEGATE / _UNDELEGATE).
const STAKE_OPS = Object.freeze({ stake: 1, delegate: 2, undelegate: 4 });
// Shared vaults (nodus-send-wasm.c "VAULTS"): at most 7 members
// (shared/dnac/msig_wire.h DNA_MSIG_MAX_N), a vault code is 18 + N × 2592
// bytes, 64 coins of the node's member query (NSW_MS_MAX_COINS), 15 approvals
// (NODUS_RT_AUTH_MAX_SIGNERS), a request's envelope part at most 64 KiB
// (NSW_MS_PREFIX_MAX).
// VAULT_MAX_APPROVAL_ATTEMPTS: approval texts handed in for one check (src/
// vaults/core.js: at most 8 per member, newest first, 7 members + own).
const VAULT_MAX_MEMBERS = 7, VAULT_MAX_COINS = 64, VAULT_MAX_APPROVAL_ATTEMPTS = 64, VAULT_ENV_MAX = 65536;
// nsw_msig_coins / nsw_msig_history: the node does not have the member query
// (nodus-send-wasm.c NSW_MS_UNSUPPORTED) — thrown as an Error with
// code 'unsupported' (src/vaults/core.js VAULT_UNSUPPORTED reads it).
const VAULT_RC_UNSUPPORTED = 2;
const VAULT_CODE = /^4e44532e4d5349472e7631(00){5}[0-9a-f]{4}([0-9a-f]{5184}){2,7}$/;

// Nodus testnet (chain born 2026-09-30, the final pre-testnet genesis). The
// chain id was read from the live genesis document; each pin is the node's
// identity/nodus.fp, re-derived as SHA3-512(nodus.pk) on every node. Six
// nodes run the WebSocket entry (Caddy TLS on 443 with an IP certificate ->
// ws_port 4005, nodus/docs/DEPLOY_RUNBOOK.md §2.4); all seven validator keys
// are pinned.
export const NODUS_SEND_NETWORK = {
  chainId: 'a48d1a785500a1cdecd739ecd53ef0e95b1dc4a7a300f49176a7fa25ae176114',
  scheme: 'wss',
  // Tried round-robin from a random start each time the module is created
  // (rotateNodusEndpoints; nodus_client then goes in list order). Each runs Caddy TLS on 443 -> the node's
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

// SMART CONTRACTS (the EVM domain, design docs/plans/2026-10-04-nodus-evm-chain-
// integration-design.md rev 3 §2) — the EVM leg's ruleset identity, which
// every envelope's call commitment binds (shared/dnac/env_wire.h
// "ruleset_hash is CONTEXTUAL"): the EVM generation's EVM runtime, version 2
// (Kurultay #9: the bridge refuses a sender with code; the address width is
// committed in the EVM_ACTIVE digest) and the digest the node's compiled
// table pins
// (nodus/src/witness/nodus_witness_runtime.h NODUS_RT_EVM_RULESET_VERSION_GEVM
// / NODUS_RT_EVM_RULESET_HASH_GEVM_INIT). The module refuses any other value
// (nsw_evm_net_set compares it with the bytes it was compiled with), so a
// stale copy here turns smart contracts off rather than signing for the wrong
// rules; `null` = smart contracts are not offered.
//
//   {
//     evmRulesetVersion: 1..2^32-1
//     evmRulesetHash:    128 lowercase hex — the EVM runtime's ruleset digest
//   }
//
// Building also needs the node to run the EVM generation (its pinned SYSTEM
// policy weighs CORE op 9 — nodus_ruleset_pins.h G3); ./client.js asks the
// node at unlock and offers nothing on a node that has not voted it in.
export const NODUS_EVM_NETWORK = Object.freeze({
  evmRulesetVersion: 2,
  evmRulesetHash: '6af8346d10c9ce5ced25b68e1ddd201be205e0d7d465e90412f78962206e775bf85f6c1d71d4cf3833148893977dc8126dfa01fcae2c83ca6a06d74c1bf4465f'
});

export function validateNodusEvmNetwork(evm) {
  const bad = what => new Error(`Smart-contract settings: ${what}.`);
  if (!evm || typeof evm !== 'object') throw bad('missing');
  const { evmRulesetVersion, evmRulesetHash } = evm;
  if (!Number.isInteger(evmRulesetVersion) || evmRulesetVersion < 1 || evmRulesetVersion > 0xffffffff) throw bad('evmRulesetVersion must be 1 to 4294967295');
  if (typeof evmRulesetHash !== 'string' || !HEX128.test(evmRulesetHash)) throw bad('evmRulesetHash must be 128 lowercase hex characters');
  return Object.freeze({ evmRulesetVersion, evmRulesetHash });
}

// The five EVM operations and their runtime_op (design §2;
// shared/dnac/evm_call_wire.h DNA_EVM_OP_*).
const EVM_OPS = Object.freeze({ call: 1, create: 2, deposit: 3, withdraw: 4, redeem: 5 });
// The §18 read methods (design rev 3 §18; ./client.js EVM_QUERY_METHODS).
const EVM_QUERY_NAMES = new Set(['evm_account', 'evm_code', 'evm_storage', 'evm_call', 'evm_estimate', 'evm_receipt', 'evm_logs', 'evm_ticket']);
const EVM_DATA_MAX = 1048576;          // nodus-send-wasm.c NSW_EVM_DATA_MAX
const EVM_INITCODE_MAX = 49152;        // evm_call_wire.h DNA_EVM_MAX_INITCODE (EIP-3860)

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

// The endpoint list starting at `start` and wrapping around: [e[s], e[s+1],
// …, e[n-1], e[0], …, e[s-1]]. The C client (nodus_client.c) always starts
// at its list's index 0, so the page rotates the list it hands over instead.
// Why: with a fixed order every page landed on the first node, and two
// devices of one account then shared a node (through node 0.25.4 the node
// kept one session per identity and the two evicted each other). A random
// start spreads page loads over the nodes; it is load spreading only —
// Math.random is enough, nothing here needs unpredictability.
export function rotateNodusEndpoints(endpoints, start) {
  const n = endpoints.length;
  if (!Number.isInteger(start) || start < 0 || start >= n) throw new Error('Invalid Nodus endpoint start index.');
  return [...endpoints.slice(start), ...endpoints.slice(0, start)];
}

export function randomNodusEndpointStart(count, random = Math.random) {
  if (!Number.isInteger(count) || count < 1) throw new Error('Invalid Nodus endpoint count.');
  return Math.min(count - 1, Math.floor(random() * count));
}

function raw(value, what) {
  if (typeof value !== 'string' || !RAW.test(value)) throw new Error(`Invalid ${what}.`);
  return value;
}

// Instantiates the module and returns the object ./client.js expects.
// `loadGlue` exists for tests (a node build of the same C, see
// test/nodus-send-wasm.test.js); the wallet always uses ./send.js.
// `startIndex` too: the endpoint the rotated list starts at (default: a
// random one, randomNodusEndpointStart).
export async function createNodusSendModule(network, { claim = null, evm = null, loadGlue = () => import('./send.js'), startIndex = null } = {}) {
  const net = validateNodusSendNetwork(network);
  const endpoints = rotateNodusEndpoints(net.endpoints, startIndex === null ? randomNodusEndpointStart(net.endpoints.length) : startIndex);
  // Smart-contract settings refused by the shape check leave smart
  // contracts off (evmError) and change nothing else.
  let evmNet = null, evmError = evm ? null : 'Smart contracts are not available on this network yet.';
  if (evm) { try { evmNet = validateNodusEvmNetwork(evm); } catch (error) { evmError = error.message; } }
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
  for (const endpoint of endpoints) check(num('nsw_net_add_endpoint', ['string', 'number'], [endpoint.host, endpoint.port]));
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
  if (evmNet) {
    try { check(num('nsw_evm_net_set', ['string', 'string'], [String(evmNet.evmRulesetVersion), evmNet.evmRulesetHash])); }
    catch (error) { evmError = error.message; }
  }
  const evmReady = () => { if (evmError) throw new Error(evmError); };
  // The request of one EVM build (evmBuild / evmBuildOffline): checked, then
  // the coins, estimate, data, access list and effect ceilings written into
  // module memory (a bridge op gets no data and no access list: the module
  // refuses them). Returns the op's runtime_op.
  const evmRequest = ({ op, to, valueWei, gasLimit, nonce, data, accessList, amount, dest, ticketId, units, estimateUnits, estimateGas, effects, effectBytes, expiryHeight, coins }) => {
    const code = typeof op === 'string' && Object.hasOwn(EVM_OPS, op) ? EVM_OPS[op] : 0;
    if (!code) throw new Error('Unknown smart-contract action.');
    if (op === 'call' && (typeof to !== 'string' || !HEX64.test(to))) throw new Error('Enter a contract address: 64 characters, 0-9 and a-f.');
    if ((op === 'call' || op === 'create') && (typeof valueWei !== 'string' || !HEX64.test(valueWei))) throw new Error('Invalid value.');
    if ((op === 'withdraw' || op === 'redeem') && (typeof dest !== 'string' || !HEX128.test(dest))) throw new Error('Enter a Nodus address: 128 characters, 0-9 and a-f.');
    if (op === 'redeem' && (typeof ticketId !== 'string' || !HEX128.test(ticketId))) throw new Error('Invalid withdrawal ticket.');
    if (!(data instanceof Uint8Array) || data.length > (op === 'create' ? EVM_INITCODE_MAX : EVM_DATA_MAX)) throw new Error('The contract data is too large.');
    if (!Array.isArray(accessList)) throw new Error('Invalid access list.');
    if (!Number.isInteger(effects) || !Number.isInteger(effectBytes)) throw new Error('Invalid effect ceiling.');
    raw(gasLimit, 'gas limit'); raw(nonce, 'nonce'); raw(amount, 'amount'); raw(units, 'resource ceiling'); raw(expiryHeight, 'validity height');
    raw(estimateUnits, 'estimate'); raw(estimateGas, 'estimate');
    loadCoins(coins);
    check(num('nsw_evm_set_estimate', ['string', 'string'], [estimateUnits, estimateGas]));
    num('nsw_evm_access_reset');
    if (data.length) {
      const at = num('nsw_evm_data_alloc', ['number'], [data.length]);
      if (!at) throw new Error('Out of memory.');
      M.HEAPU8.set(data, at);
    } else {
      num('nsw_evm_data_alloc', ['number'], [0]);
    }
    for (const entry of accessList) {
      if (!entry || typeof entry.address !== 'string' || !HEX64.test(entry.address) || !Array.isArray(entry.storageKeys) || !entry.storageKeys.every(k => typeof k === 'string' && HEX64.test(k))) throw new Error('Invalid access list.');
      check(num('nsw_evm_access_add', ['string', 'string'], [entry.address, entry.storageKeys.join('')]));
    }
    check(num('nsw_evm_set_decl', ['number', 'number'], [effects, effectBytes]));
    return code;
  };
  // What the last EVM build signed, read back from its bytes by the C side.
  const evmBuilt = op => {
    const at = num('nsw_built_env'), length = num('nsw_built_env_len');
    const inputs = [];
    for (let i = 0, n = num('nsw_built_n_in'); i < n; i++) inputs.push(str('nsw_built_in', ['number'], [i]));
    const opName = Object.keys(EVM_OPS).find(name => EVM_OPS[name] === num('nsw_evm_built_op'));
    if (opName !== op) throw new Error('The built transaction does not match the request.');
    return {
      envelope: M.HEAPU8.slice(at, at + length),
      intentId: str('nsw_built_intent'),
      decoded: {
        op: opName, to: str('nsw_evm_built_to'), valueWei: str('nsw_evm_built_value'), gasLimit: str('nsw_evm_built_gas'),
        nonce: str('nsw_evm_built_nonce'), units: str('nsw_evm_built_units'), amount: str('nsw_evm_built_amount'),
        dest: str('nsw_evm_built_dest'), ticketId: str('nsw_evm_built_ticket'), dataLength: num('nsw_evm_built_data_len'),
        // CREATE only: the new contract's address from the signed sender
        // and nonce (red-team 1 F11; '' for every other op)
        created: str('nsw_evm_built_created'),
        recipient: str('nsw_built_recipient'), fee: str('nsw_built_fee'), change: str('nsw_built_change'),
        expiryHeight: str('nsw_built_expiry'), chainId: str('nsw_built_chain'), inputs
      }
    };
  };
  const loadCoins = coins => {
    if (!Array.isArray(coins) || coins.length > MAX_COINS) throw new Error('Invalid coin list.');
    num('nsw_req_reset');
    for (const coin of coins) {
      if (!coin || typeof coin.nullifier !== 'string' || !HEX128.test(coin.nullifier)) throw new Error('Invalid coin list.');
      check(num('nsw_req_add_coin', ['string', 'string'], [coin.nullifier, raw(coin.amount, 'coin amount')]));
    }
  };
  // Messages bridge (NC-4b): only nc_* entry points; the async form only
  // inside the queue (connect()), never from connectSync().
  const ncName = name => { if (typeof name !== 'string' || !name.startsWith('nc_')) throw new Error('Not a Messages entry point.'); return name; };
  const connectApi = async => Object.freeze({
    num: (name, types = [], args = []) => num(ncName(name), types, args),
    str: (name, types = [], args = []) => str(ncName(name), types, args),
    ...(async ? { call: (name, types = [], args = []) => call(ncName(name), types, args) } : {}),
    heap: () => M.HEAPU8
  });
  const WINDOW = ['open', 'not-open', 'closed'], CLAIMED = ['no-evidence', 'yes', 'unknown'];
  // SHARED VAULTS: the vault in use, its coins, a payment request's
  // parts, the read-back (shapes in src/vaults/core.js).
  const vaultLoad = descriptor => {
    if (typeof descriptor !== 'string' || !VAULT_CODE.test(descriptor)) throw new Error('This is not a valid vault.');
    check(num('nsw_msig_load', ['string'], [descriptor]));
  };
  const vaultInfo = () => {
    const members = [];
    for (let i = 0, n = num('nsw_msig_n'); i < n; i++) members.push(str('nsw_msig_member', ['number'], [i]));
    return { descriptor: str('nsw_msig_desc_hex'), address: str('nsw_msig_addr'), m: num('nsw_msig_m'), n: num('nsw_msig_n'), members, isMember: num('nsw_msig_is_member') === 1 };
  };
  const vaultCoinsLoad = coins => {
    if (!Array.isArray(coins) || coins.length > VAULT_MAX_COINS) throw new Error('Invalid vault coins.');
    num('nsw_msig_coins_reset');
    for (const c of coins) {
      if (!c || typeof c.id !== 'string' || !HEX128.test(c.id)) throw new Error('Invalid vault coins.');
      check(num('nsw_msig_coin_add', ['string', 'string', 'string', 'string'], [c.id, raw(c.amount, 'coin amount'), raw(c.unlock, 'coin lock height'), raw(c.height, 'block height')]));
    }
  };
  // The rc of nsw_msig_coins / nsw_msig_history: 0 passes; the node without
  // the member query -> an Error with code 'unsupported' (its text the
  // module's fixed one); anything else -> the module's reason.
  const vaultQueryCheck = rc => {
    if (rc === VAULT_RC_UNSUPPORTED) throw Object.assign(new Error(str('nsw_error') || 'This Nodus node is not updated yet for shared vaults. Try again later.'), { code: 'unsupported' });
    check(rc);
  };
  const vaultRequest = () => ({ chain: str('nsw_msig_prop_chain'), tip: str('nsw_msig_prop_tip'), signers: str('nsw_msig_prop_signers'), digest: str('nsw_msig_prop_digest'), env: str('nsw_msig_prop_env') });
  const vaultRequestLoad = request => {
    const r = request || {};
    if (typeof r.chain !== 'string' || !HEX64.test(r.chain) || typeof r.digest !== 'string' || !HEX128.test(r.digest) ||
        typeof r.env !== 'string' || !/^([0-9a-f]{2})+$/.test(r.env) || r.env.length > 2 * VAULT_ENV_MAX) throw new Error('This payment request is damaged.');
    check(num('nsw_msig_prop_in', ['string', 'string', 'string', 'string', 'string'], [r.chain, raw(r.tip, 'block height'), raw(r.signers, 'approval count'), r.digest, r.env]));
  };
  // F2: each approval verified by the module against the request in use;
  // only verified ones are kept (one per key). Bounded by attempts, never by
  // a count of unverified approvals shadowing a verified one.
  const vaultApprovalsLoad = approvals => {
    if (!Array.isArray(approvals) || approvals.length > VAULT_MAX_APPROVAL_ATTEMPTS ||
        !approvals.every(a => a && typeof a.text === 'string' && typeof a.sender === 'string' && HEX128.test(a.sender))) throw new Error('Invalid approvals.');
    num('nsw_msig_sig_reset');
    let refused = 0;
    for (const a of approvals) if (num('nsw_msig_sig_add', ['string', 'string'], [a.text, a.sender]) < 0) refused++;
    const verifiedSigners = [];
    for (let i = 0, n = num('nsw_msig_sig_count'); i < n; i++) verifiedSigners.push(str('nsw_msig_sig_signer', ['number'], [i]));
    return { verifiedSigners, refused };
  };
  const vaultReviewRead = () => {
    const inputs = [], outputs = [];
    for (let i = 0, n = num('nsw_msig_rv_n_in'); i < n; i++) inputs.push(str('nsw_msig_rv_in', ['number'], [i]));
    for (let i = 0, n = num('nsw_msig_rv_n_out'); i < n; i++) {
      outputs.push({ owner: str('nsw_msig_rv_out_owner', ['number'], [i]), amount: str('nsw_msig_rv_out_amount', ['number'], [i]), change: num('nsw_msig_rv_out_change', ['number'], [i]) === 1 });
    }
    return {
      vault: str('nsw_msig_rv_vault'), m: num('nsw_msig_rv_m'), n: num('nsw_msig_rv_n'), approvals: num('nsw_msig_rv_k'),
      fee: str('nsw_msig_rv_fee'), expiryHeight: str('nsw_msig_rv_expiry'), tip: str('nsw_msig_rv_now'),
      expired: num('nsw_msig_rv_expired') === 1, member: num('nsw_msig_rv_member') === 1,
      intentId: str('nsw_msig_rv_intent'), digest: str('nsw_msig_prop_digest'), inputs, outputs
    };
  };

  const api = {
    async unlock({ seed } = {}) {
      if (!(seed instanceof Uint8Array) || seed.length !== 32) throw new Error('Nodus signing seed must be 32 bytes.');
      // The C side wipes this copy on every path (nsw_unlock); the caller
      // wipes its own (./client.js unlock).
      M.HEAPU8.set(seed, num('nsw_seed_buf'));
      check(await call('nsw_unlock'));
      return { fingerprint: str('nsw_fingerprint'), chainId: str('nsw_chain_hex') };
    },
    // The same unlock in two steps (./client.js identify / connectNetwork).
    // identify({ seed }): the identity from the seed — no client, nothing
    // sent (nodus-send-wasm.c nsw_identify); resolves as unlock() does.
    async identify({ seed } = {}) {
      if (!(seed instanceof Uint8Array) || seed.length !== 32) throw new Error('Nodus signing seed must be 32 bytes.');
      // The C side wipes this copy on every path (nsw_identify).
      M.HEAPU8.set(seed, num('nsw_seed_buf'));
      check(await call('nsw_identify'));
      return { fingerprint: str('nsw_fingerprint'), chainId: str('nsw_chain_hex') };
    },
    // connectNetwork(): the pinned session + the chain check (nsw_connect).
    // A failure may be tried again, except one marked `final` (the node
    // serves another chain: the module refuses to connect from then on).
    async connectNetwork() {
      const rc = await call('nsw_connect');
      if (rc === 0) return;
      const error = failure();
      if (rc === -2) error.final = true;
      throw error;
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
        // the full-wire id (preflight wire_id) — what the node's address
        // history lists the transaction by (src/adapters/nodus.js builtWire)
        wireId: str('nsw_built_wire'),
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
    // HF-4 (design docs/plans/2026-10-02-onchain-names-design.md rev 4
    // §1.6). rulesetInfo() -> { tip, generation, gen2Height }: the pinned
    // rule-set generation whose tuple equals the node's dnac_ruleset_info
    // answer (the module refuses an older node and an unknown generation),
    // that answer's tip and "H" (0 = no switch committed) — decimal
    // strings. Only for the expiry the wallet requests; every build asks
    // the node again (nodus-send-wasm.c nsw_select_generation).
    async rulesetInfo() {
      check(await call('nsw_ruleset_info'));
      return { tip: str('nsw_ri_tip'), generation: String(num('nsw_ri_gen')), gen2Height: str('nsw_ri_h') };
    },
    // ACCOUNT HISTORY (0.1.78; nodus-send-wasm.c "ACCOUNT HISTORY", decision
    // 2026-10-01-node-address-history-index.md item 6): one dnac_addr_history
    // page of THIS wallet's own address (the module always asks for its
    // session's fingerprint — the node answers nobody else's, C11).
    // addrHistory({ before?: { h, i, q }, limit }) -> the page as plain JS
    // ({ enabled, from_height, entries: [{ h, i, q, kind, amount, token, fee,
    // peer, wire, ts }] }, every u64 a decimal string, bytes lowercase hex);
    // ./client.js checks it (src/nodus/history.js parseAddrHistory).
    async addrHistory({ before, limit } = {}) {
      if (!Number.isSafeInteger(limit) || limit < 1 || limit > ADDR_HISTORY_MAX_LIMIT) throw new Error('Invalid account history request.');
      let at = ['', '0', '0'];
      if (before !== undefined) {
        if (!before || typeof before !== 'object') throw new Error('Invalid account history request.');
        at = [raw(before.h, 'block height'), raw(before.i, 'history position'), raw(before.q, 'history position')];
        if (BigInt(at[1]) > 0xffffffffn || BigInt(at[2]) > 0xffffffffn) throw new Error('Invalid account history request.');
      }
      check(await call('nsw_addr_history', ['string', 'string', 'string', 'number'], [...at, limit]));
      return JSON.parse(str('nsw_addr_history_json'));
    },
    // Chain names: ONE node's committed state (decision
    // 2026-10-02-onchain-names.md item 9). nameLookup({ name }) -> { found,
    // committedHeight, owner?, registeredHeight? }; nameOf({ owner }) ->
    // { found, committedHeight, name?, registeredHeight? }. `name` must
    // already be lowercase (src/nodus/names.js).
    async nameLookup({ name } = {}) {
      if (typeof name !== 'string' || num('nsw_name_ok', ['string'], [name]) !== 1) throw new Error('Not a chain name: 3 to 36 letters a-z and digits.');
      check(await call('nsw_name_lookup', ['string'], [name]));
      return num('nsw_name_found') === 1
        ? { found: true, committedHeight: str('nsw_name_committed'), owner: str('nsw_name_owner'), registeredHeight: str('nsw_name_registered') }
        : { found: false, committedHeight: str('nsw_name_committed') };
    },
    async nameOf({ owner } = {}) {
      if (typeof owner !== 'string' || !HEX128.test(owner)) throw new Error('Invalid Nodus address.');
      check(await call('nsw_name_of', ['string'], [owner]));
      return num('nsw_name_found') === 1
        ? { found: true, committedHeight: str('nsw_name_committed'), name: str('nsw_name_name'), registeredHeight: str('nsw_name_registered') }
        : { found: false, committedHeight: str('nsw_name_committed') };
    },
    // profileAddress({ owner, field: 'eth' | 'bsc' | 'sol' | 'trx' }) ->
    // { address }: the address the owner published in its profile, read and
    // signature-checked by the module (connect/nc_profile.c); an unreadable,
    // unsigned or field-less profile rejects.
    async profileAddress({ owner, field } = {}) {
      if (typeof owner !== 'string' || !HEX128.test(owner)) throw new Error('Invalid Nodus address.');
      if (!['eth', 'bsc', 'sol', 'trx'].includes(field)) throw new Error('This network has no profile address field.');
      check(await call('nsw_profile_address', ['string', 'string'], [owner, field]));
      return { address: str('nsw_profile_addr') };
    },
    // CHAIN-NAME REGISTRATION — nodus-cli `name register` over the shared
    // builder (nodus-send-wasm.c "CHAIN NAME REGISTRATION"; decision
    // 2026-10-02-onchain-names.md). namePrices() -> { prices: [3, 4, 5, 6+
    // characters] (raw decimal strings: dnac_fee_info "np" at tip + 1),
    // scheduled: [{ param (10..13), value, effective }] } — for display;
    // the build reads the price again on its own call.
    async namePrices() {
      check(await call('nsw_name_prices'));
      const scheduled = [];
      for (let i = 0, n = num('nsw_np_sched_count'); i < n; i++) {
        scheduled.push({ param: num('nsw_np_sched_param', ['number'], [i]), value: str('nsw_np_sched_value', ['number'], [i]), effective: str('nsw_np_sched_effective', ['number'], [i]) });
      }
      return { prices: [0, 1, 2, 3].map(i => str('nsw_np_price', ['number'], [i])), scheduled };
    },
    // nameBuild({ name (lower-case), expiryHeight, coins }) -> { envelope,
    // intentId, decoded: { name, price, owner, fee, change, expiryHeight,
    // chainId, inputs } }, `decoded` read back from the signed bytes by the
    // C side. NO price is passed in: the module reads it from the node on
    // this call (never a compiled or JS value), after checking that the
    // name is free and this ID holds none. Submitted with submit().
    async nameBuild({ name, expiryHeight, coins } = {}) {
      if (typeof name !== 'string' || num('nsw_name_ok', ['string'], [name]) !== 1) throw new Error('Not a chain name: 3 to 36 letters a-z and digits.');
      raw(expiryHeight, 'validity height');
      if (!Array.isArray(coins) || coins.length > MAX_COINS) throw new Error('Invalid coin list.');
      num('nsw_req_reset');
      for (const coin of coins) {
        if (!coin || typeof coin.nullifier !== 'string' || !HEX128.test(coin.nullifier)) throw new Error('Invalid coin list.');
        check(num('nsw_req_add_coin', ['string', 'string'], [coin.nullifier, raw(coin.amount, 'coin amount')]));
      }
      check(await call('nsw_name_build', ['string', 'string'], [name, expiryHeight]));
      const at = num('nsw_built_env'), length = num('nsw_built_env_len');
      const inputs = [];
      for (let i = 0, n = num('nsw_built_n_in'); i < n; i++) inputs.push(str('nsw_built_in', ['number'], [i]));
      return {
        envelope: M.HEAPU8.slice(at, at + length),
        intentId: str('nsw_built_intent'),
        wireId: str('nsw_built_wire'),
        decoded: {
          name: str('nsw_built_name'), price: str('nsw_built_price'), owner: str('nsw_built_recipient'), fee: str('nsw_built_fee'),
          change: str('nsw_built_change'), expiryHeight: str('nsw_built_expiry'), chainId: str('nsw_built_chain'), inputs
        }
      };
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
    // STAKING (0.1.29) — nodus-cli `v2-envelope stake | delegate |
    // undelegate` over the shared builder (nodus-send-wasm.c "STAKING").
    // The chain constants, read from the module (dnac.h), never restated.
    stakingRules: Object.freeze({
      minDelegation: str('nsw_const_min_delegation'), selfStake: str('nsw_const_self_stake'),
      commissionMaxBps: str('nsw_const_commission_max'), undelegateLockEpochs: str('nsw_const_undelegate_lock_epochs'),
      epochLength: str('nsw_const_epoch_length'),
      // the per-validator delegator cap (nodus_types.h
      // NODUS_MAX_DELEGATORS_PER_VALIDATOR), the "/2048" of a row's slots
      maxDelegators: str('nsw_const_max_delegators')
    }),
    // validators() -> { truncated, validators: [{ fingerprint (derived by
    // the module from the key), selfStake, delegated (raw), commissionBps,
    // status (0 active, 1 retiring, 2 unstaked, 3 auto-retired, 4 eligible),
    // delegators (filled delegator slots; -1 = the node's answer carries no
    // count — an older node — unknown, never 0) }] }
    async validators() {
      check(await call('nsw_validators'));
      const validators = [];
      for (let i = 0, n = num('nsw_val_count'); i < n; i++) {
        validators.push({
          fingerprint: str('nsw_val_fp', ['number'], [i]), selfStake: str('nsw_val_self', ['number'], [i]),
          delegated: str('nsw_val_delegated', ['number'], [i]), commissionBps: num('nsw_val_commission', ['number'], [i]),
          status: num('nsw_val_status', ['number'], [i]), delegators: num('nsw_val_delegators', ['number'], [i])
        });
      }
      return { truncated: num('nsw_val_truncated') === 1, validators };
    },
    // delegations() -> [{ validator: 128 hex fingerprint, amount, block }]
    async delegations() {
      check(await call('nsw_delegations'));
      const rows = [];
      for (let i = 0, n = num('nsw_del_count'); i < n; i++) {
        rows.push({ validator: str('nsw_del_fp', ['number'], [i]), amount: str('nsw_del_amount', ['number'], [i]), block: str('nsw_del_block', ['number'], [i]) });
      }
      return rows;
    },
    // stakeBuild({ op: 'stake' | 'delegate' | 'undelegate', validator (128
    // hex, '' for stake), amount, commissionBps (stake), expiryHeight, coins })
    // -> { envelope, intentId, decoded: { op, validator, amount,
    // commissionBps, fee, change, expiryHeight, chainId, inputs } }, `decoded`
    // read back from the signed bytes by the C side. Submitted with submit().
    async stakeBuild({ op, validator = '', amount, commissionBps = '0', expiryHeight, coins } = {}) {
      const code = typeof op === 'string' && Object.hasOwn(STAKE_OPS, op) ? STAKE_OPS[op] : 0;
      if (!code) throw new Error('Unknown staking action.');
      if (op === 'stake' ? validator !== '' : typeof validator !== 'string' || !HEX128.test(validator)) throw new Error('Invalid witness.');
      raw(amount, 'amount'); raw(commissionBps, 'commission'); raw(expiryHeight, 'validity height');
      if (!Array.isArray(coins) || coins.length > MAX_COINS) throw new Error('Invalid coin list.');
      num('nsw_req_reset');
      for (const coin of coins) {
        if (!coin || typeof coin.nullifier !== 'string' || !HEX128.test(coin.nullifier)) throw new Error('Invalid coin list.');
        check(num('nsw_req_add_coin', ['string', 'string'], [coin.nullifier, raw(coin.amount, 'coin amount')]));
      }
      check(await call('nsw_stake_build', ['number', 'string', 'string', 'string', 'string'], [code, validator, amount, commissionBps, expiryHeight]));
      const at = num('nsw_built_env'), length = num('nsw_built_env_len');
      const inputs = [];
      for (let i = 0, n = num('nsw_built_n_in'); i < n; i++) inputs.push(str('nsw_built_in', ['number'], [i]));
      const opName = Object.keys(STAKE_OPS).find(name => STAKE_OPS[name] === num('nsw_built_op'));
      return {
        envelope: M.HEAPU8.slice(at, at + length),
        intentId: str('nsw_built_intent'),
        wireId: str('nsw_built_wire'),
        decoded: {
          op: opName, validator: str('nsw_built_recipient'), amount: str('nsw_built_amount'),
          commissionBps: op === 'stake' ? str('nsw_built_commission') : '0', fee: str('nsw_built_fee'),
          change: str('nsw_built_change'), expiryHeight: str('nsw_built_expiry'), chainId: str('nsw_built_chain'), inputs
        }
      };
    },
    // SHARED VAULTS — general multisig (nodus-send-wasm.c "VAULTS"; decision
    // 2026-09-29-general-multisig.md). Every operation names its vault by
    // its code (the descriptor, lowercase hex) and loads it first: the
    // module holds ONE vault in use. Member IDs, the address and every
    // field of a payment are computed or read back by the C side.
    // vaultCreate({ members: [128 hex ID], includeSelf, m }) -> vaultInfo
    async vaultCreate({ members, includeSelf = true, m } = {}) {
      if (!Array.isArray(members) || members.length > VAULT_MAX_MEMBERS || !members.every(fp => typeof fp === 'string' && HEX128.test(fp))) throw new Error('Invalid vault members.');
      if (!Number.isInteger(m) || m < 1 || m > VAULT_MAX_MEMBERS) throw new Error('Invalid number of approvals.');
      num('nsw_msig_member_reset');
      if (includeSelf) check(num('nsw_msig_member_add_self'));
      for (const fp of members) check(await call('nsw_msig_member_add', ['string'], [fp]));
      check(num('nsw_msig_create', ['number'], [m]));
      return vaultInfo();
    },
    // vaultOpen({ descriptor }) -> { descriptor, address, m, n, members, isMember }
    async vaultOpen({ descriptor } = {}) {
      vaultLoad(descriptor);
      return vaultInfo();
    },
    // vaultBalance({ descriptor }) -> { total, spendable } (raw decimal)
    async vaultBalance({ descriptor } = {}) {
      vaultLoad(descriptor);
      check(await call('nsw_msig_balance'));
      return { total: str('nsw_msig_bal_total'), spendable: str('nsw_msig_bal_spendable') };
    },
    // vaultCoins({ descriptor }) -> { coins: [{ id, amount, unlock, height }],
    // truncated }: ONE member query (dnac_msig_utxo, design 2026-09-29-
    // general-multisig §8.6 rev 2): the vault's native coins, largest first,
    // at most 64; `truncated` = the node has more, or more than 64 came.
    // Only a member's session gets an answer. A node without the query
    // throws an Error with code 'unsupported' (no block reading is done
    // instead — the decision of Kurultay #15).
    async vaultCoins({ descriptor } = {}) {
      vaultLoad(descriptor);
      vaultQueryCheck(await call('nsw_msig_coins'));
      const coins = [];
      for (let i = 0, n = num('nsw_msig_coin_count'); i < n; i++) {
        coins.push({ id: str('nsw_msig_coin_id', ['number'], [i]), amount: str('nsw_msig_coin_amount', ['number'], [i]), unlock: str('nsw_msig_coin_unlock', ['number'], [i]), height: str('nsw_msig_coin_height', ['number'], [i]) });
      }
      return { coins, truncated: num('nsw_msig_coins_full') === 1 };
    },
    // vaultHistory({ descriptor, before?: { h, i, q }, limit }) -> one
    // dnac_msig_addr_history page of the VAULT's address, the same shape as
    // addrHistory ({ enabled, from_height, entries }); ./client.js checks it
    // (src/nodus/history.js parseAddrHistory). Member gate and 'unsupported'
    // as vaultCoins.
    async vaultHistory({ descriptor, before, limit } = {}) {
      if (!Number.isSafeInteger(limit) || limit < 1 || limit > ADDR_HISTORY_MAX_LIMIT) throw new Error('Invalid vault history request.');
      let at = ['', '0', '0'];
      if (before !== undefined) {
        if (!before || typeof before !== 'object') throw new Error('Invalid vault history request.');
        at = [raw(before.h, 'block height'), raw(before.i, 'history position'), raw(before.q, 'history position')];
        if (BigInt(at[1]) > 0xffffffffn || BigInt(at[2]) > 0xffffffffn) throw new Error('Invalid vault history request.');
      }
      vaultLoad(descriptor);
      vaultQueryCheck(await call('nsw_msig_history', ['string', 'string', 'string', 'number'], [...at, limit]));
      return JSON.parse(str('nsw_msig_history_json'));
    },
    // vaultPropose({ descriptor, coins, to, amount }) -> { request, exportText,
    // review }: request = the parts a message carries ({ chain, tip, signers,
    // digest, env }); exportText = nodus-cli's export file; review read back.
    async vaultPropose({ descriptor, coins = [], to, amount } = {}) {
      if (typeof to !== 'string' || !HEX128.test(to)) throw new Error('Enter a Nodus address: 128 characters, 0-9 and a-f.');
      raw(amount, 'amount');
      vaultLoad(descriptor);
      vaultCoinsLoad(coins);
      check(await call('nsw_msig_build', ['string', 'string'], [to, amount]));
      return { request: vaultRequest(), exportText: str('nsw_msig_text'), review: vaultReviewRead() };
    },
    // vaultReview({ descriptor, coins, request }) -> review (at the node's
    // tip). coins: the vault's own coins (its record) — the review REFUSES a
    // request that spends any other coin (F1).
    // approvals: [{ text (nodus-cli's signature text), sender (the ID it
    // came from) }] — each VERIFIED in the module (F2: nsw_msig_sig_add);
    // the answer's `verifiedSigners` lists the IDs whose approval verified
    // (one per key) and `refused` how many did not.
    async vaultReview({ descriptor, coins = [], request, approvals = [] } = {}) {
      vaultLoad(descriptor);
      vaultCoinsLoad(coins);
      vaultRequestLoad(request);
      check(await call('nsw_msig_review'));
      return { ...vaultReviewRead(), ...vaultApprovalsLoad(approvals) };
    },
    // vaultApprove({ descriptor, request, digest }) -> { signature (nodus-cli's
    // signature text), review }. Reviews again at the node's tip and signs
    // only if the request is still the one shown (`digest`).
    async vaultApprove({ descriptor, coins = [], request, digest } = {}) {
      if (typeof digest !== 'string' || !HEX128.test(digest)) throw new Error('Invalid payment request.');
      vaultLoad(descriptor);
      vaultCoinsLoad(coins);
      vaultRequestLoad(request);
      check(await call('nsw_msig_review'));
      if (str('nsw_msig_prop_digest') !== digest) throw new Error('This payment request changed after it was shown. Nothing was signed.');
      const review = vaultReviewRead();
      check(num('nsw_msig_sign'));
      return { signature: str('nsw_msig_text'), review };
    },
    // vaultSubmit({ descriptor, coins, request, digest, approvals: [{ text,
    // sender }] }) -> { accepted, message?, intentId, wireId, review (with
    // verifiedSigners / refused) }: only verified approvals are combined.
    // wireId: the combined envelope's full-wire id — what the vault's
    // history rows carry ("wire"), so the page can tell this payment landed.
    async vaultSubmit({ descriptor, coins = [], request, digest, approvals = [] } = {}) {
      if (typeof digest !== 'string' || !HEX128.test(digest)) throw new Error('Invalid payment request.');
      vaultLoad(descriptor);
      vaultCoinsLoad(coins);
      vaultRequestLoad(request);
      check(await call('nsw_msig_review'));
      if (str('nsw_msig_prop_digest') !== digest) throw new Error('This payment request changed after it was shown. Nothing was sent.');
      const review = { ...vaultReviewRead(), ...vaultApprovalsLoad(approvals) };
      const rc = await call('nsw_msig_submit');
      const intentId = str('nsw_msig_intent'), wireId = str('nsw_msig_wire');
      if (rc === 0) return { accepted: true, intentId, wireId, review };
      if (rc === 1) return { accepted: false, message: str('nsw_error'), intentId, wireId, review };
      throw failure();
    },
    // SMART CONTRACTS — the EVM domain (nodus-send-wasm.c "SMART
    // CONTRACTS"; design docs/plans/2026-10-04-nodus-evm-chain-integration-
    // design.md rev 3 §2). evmBuild({ op: 'call' | 'create' | 'deposit' |
    // 'withdraw' | 'redeem', to (64 hex, call), valueWei (64 hex u256,
    // call / create), gasLimit, nonce (not redeem), data (Uint8Array: call
    // data / initcode), accessList ([{ address: 64 hex, storageKeys: [64
    // hex] }]), amount (raw, bridge ops), dest (128 hex, withdraw / redeem),
    // ticketId (128 hex, redeem), units (the declared resource ceiling; '0'
    // = the smallest the node accepts — give evm_estimate's for a call),
    // effects / effectBytes (call / create; 0 = default), expiryHeight,
    // coins }) -> { envelope, intentId, decoded: { op, to, valueWei,
    // gasLimit, nonce, units, amount, dest, ticketId, dataLength, recipient,
    // fee, change, expiryHeight, chainId, inputs } }, `decoded` read back
    // from the signed bytes by the C side. Submitted with submit().
    // Offered only when the smart-contract settings were accepted (removed
    // below otherwise; ./client.js then reports evmBuildable false).
    // estimateUnits / estimateGas: the node's evm_estimate `ue` / `ge` for a
    // call / create built with units '0' — the module adds the read units
    // they imply to its own shape's minimum (client/nodus_v2_evm.h "UNITS").
    async evmBuild({ op, to = '', valueWei = '0'.repeat(64), gasLimit = '0', nonce = '0', data = new Uint8Array(0), accessList = [], amount = '0', dest = '', ticketId = '', units = '0', estimateUnits = '0', estimateGas = '0', effects = 0, effectBytes = 0, expiryHeight, coins } = {}) {
      evmReady();
      evmRequest({ op, to, valueWei, gasLimit, nonce, data, accessList, amount, dest, ticketId, units, estimateUnits, estimateGas, effects, effectBytes, expiryHeight, coins });
      let rc;
      if (op === 'call') rc = await call('nsw_evm_call', ['string', 'string', 'string', 'string', 'string', 'string'], [to, valueWei, gasLimit, nonce, units, expiryHeight]);
      else if (op === 'create') rc = await call('nsw_evm_create', ['string', 'string', 'string', 'string', 'string'], [valueWei, gasLimit, nonce, units, expiryHeight]);
      else if (op === 'deposit') rc = await call('nsw_evm_deposit', ['string', 'string', 'string', 'string'], [amount, nonce, units, expiryHeight]);
      else if (op === 'withdraw') rc = await call('nsw_evm_withdraw', ['string', 'string', 'string', 'string', 'string'], [amount, nonce, dest, units, expiryHeight]);
      else rc = await call('nsw_evm_redeem', ['string', 'string', 'string', 'string', 'string'], [ticketId, amount, dest, units, expiryHeight]);
      check(rc);
      return evmBuilt(op);
    },
    // evmBuildOffline({ seed, generation, chainId, tip, gasPrice, ...the
    // evmBuild fields }) -> the evmBuild result. The OFFLINE build (0.1.64,
    // nodus-send-wasm.c nsw_evm_offline_build): no session, no node — the
    // identity from `seed` (Uint8Array(32), the ML-DSA-87 signing seed; the
    // C side wipes its copy on every path, the caller wipes its own), and
    // every network fact given: `generation` (a pinned rule-set generation
    // that carries the EVM — evmGeneration or above), `chainId` (64 hex),
    // `tip` and `gasPrice` (decimal, as the node would report them); the EVM
    // leg's ruleset identity is this module's accepted smart-contract
    // setting. `expiryHeight` must be tip + 90. The SAME shared builder as
    // evmBuild, so `decoded` is read back from the signed bytes the same
    // way. Fields the op does not carry are not passed on (as evmBuild).
    // Submitting the result is the caller's (submit() needs a session).
    async evmBuildOffline({ seed, generation, chainId, tip, gasPrice, op, to = '', valueWei = '0'.repeat(64), gasLimit = '0', nonce = '0', data = new Uint8Array(0), accessList = [], amount = '0', dest = '', ticketId = '', units = '0', estimateUnits = '0', estimateGas = '0', effects = 0, effectBytes = 0, expiryHeight, coins } = {}) {
      evmReady();
      if (!(seed instanceof Uint8Array) || seed.length !== 32) throw new Error('Nodus signing seed must be 32 bytes.');
      if (!Number.isInteger(generation) || generation < 1 || generation > 0xffff) throw new Error('Invalid rule-set generation.');
      if (typeof chainId !== 'string' || !HEX64.test(chainId)) throw new Error('Invalid chain id.');
      raw(tip, 'block height'); raw(gasPrice, 'gas price');
      const code = evmRequest({ op, to, valueWei, gasLimit, nonce, data, accessList, amount, dest, ticketId, units, estimateUnits, estimateGas, effects, effectBytes, expiryHeight, coins });
      const vm = op === 'call' || op === 'create';
      // The C side wipes this copy on every path (nsw_evm_offline_build).
      M.HEAPU8.set(seed, num('nsw_seed_buf'));
      check(num('nsw_evm_offline_build',
        ['number', 'number', 'string', 'string', 'string', 'string', 'string', 'string', 'string', 'string', 'string', 'string', 'string', 'string', 'string', 'string'],
        [generation, code, chainId, tip, gasPrice, String(evmNet.evmRulesetVersion), evmNet.evmRulesetHash,
          op === 'call' ? to : '', vm ? valueWei : '', vm ? gasLimit : '0', op === 'redeem' ? '0' : nonce, vm ? '0' : amount,
          op === 'withdraw' || op === 'redeem' ? dest : '', op === 'redeem' ? ticketId : '', units, expiryHeight]));
      return evmBuilt(op);
    },
    // SMART CONTRACTS — the §18 reads (nodus-send-wasm.c nsw_evm_query):
    // evmQuery({ method, args }) where `method` is one of the eight evm_*
    // names and `args` maps each CBOR key to ['b', lowercase hex], ['u',
    // decimal] or ['U', [1..3 decimals]] (a CBOR array of u64 — the
    // evm_logs cursor "c" = [h, x, li], red-team 1 F4; written as
    // `key=U:a,b,c`, nodus-send-wasm.c nsw_evm_args_cbor) (./client.js
    // evmArgs builds it). The argument text goes into
    // module memory (call data can exceed a ccall string's stack copy); the
    // reply map comes back as JSON (uint and bstr as strings) and is checked
    // by src/evm/rpc.js before anyone sees it.
    async evmQuery({ method, args = {} } = {}) {
      if (typeof method !== 'string' || !EVM_QUERY_NAMES.has(method)) throw new Error('Unknown smart-contract request.');
      if (!args || typeof args !== 'object') throw new Error('Invalid smart-contract request.');
      const parts = [];
      const u64 = v => typeof v === 'string' && /^(0|[1-9]\d{0,19})$/.test(v) && BigInt(v) < 2n ** 64n;
      for (const [key, tagged] of Object.entries(args)) {
        if (!/^[a-z0-9]{1,4}$/.test(key) || !Array.isArray(tagged) || tagged.length !== 2) throw new Error('Invalid smart-contract request.');
        const [tag, value] = tagged;
        if (tag === 'b' && typeof value === 'string' && /^([0-9a-f]{2})*$/.test(value)) parts.push(`${key}=b:${value}`);
        else if (tag === 'u' && u64(value)) parts.push(`${key}=u:${value}`);
        else if (tag === 'U' && Array.isArray(value) && value.length >= 1 && value.length <= 3 && [...value].every(u64)) parts.push(`${key}=U:${value.join(',')}`);
        else throw new Error('Invalid smart-contract request.');
      }
      const text = new TextEncoder().encode(parts.join(';'));
      const at = num('nsw_evm_query_buf', ['number'], [text.length]);
      if (!at) throw new Error('The smart-contract request is too large.');
      M.HEAPU8.set(text, at);
      check(await call('nsw_evm_query', ['string', 'number'], [method, text.length]));
      return JSON.parse(str('nsw_evm_query_json'));
    },
    // The rule-set generation that carries the EVM (./client.js offers
    // smart contracts only where the node runs it).
    evmGeneration: num('nsw_evm_generation'),
    // MESSAGES (NC-4b): the Nodus Connect exports (nc_*, connect/nc_wasm.c)
    // linked into THIS module and running on its one session. `connect(run)`
    // is an asynchronous operation like the others (./client.js runs it in
    // its one queue): `run` receives { num, str, call, heap } limited to nc_*
    // names and may await `call` (ccall async) once per step.
    // `connectSync(run)` is for the exports that never reach
    // emscripten_sleep (nc_salt_pick, nc_day_today, nc_lock, nc_error,
    // nc_result): safe while another export waits; `call` is not offered.
    async connect(run) { return run(connectApi(true)); },
    connectSync(run) { return run(connectApi(false)); },
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
  if (evmError) { delete api.evmBuild; delete api.evmBuildOffline; }
  return api;
}

// Registration point read by src/app.js: null while the network settings
// above are null (NODUS stays receive-only, src/nodus/network.js).
export const nodusSendModuleFactory = NODUS_SEND_NETWORK ? () => createNodusSendModule(NODUS_SEND_NETWORK, { claim: NODUS_CLAIM_DATA, evm: NODUS_EVM_NETWORK }) : null;
