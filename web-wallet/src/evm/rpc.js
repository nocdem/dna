// Smart contracts (the Nodus EVM domain) — the client side of the EVM read
// RPC (design docs/plans/2026-10-04-nodus-evm-chain-integration-design.md rev 3
// §18, tier-2, CBOR, the dnac_* pattern) and of the receipt encoding (§7).
//
// What crosses from the module (src/nodus/send-module.js `evmQuery`) is the
// node's CBOR reply map decoded into plain JS: unsigned integers as decimal
// strings, byte strings as lowercase hex, booleans, arrays, maps as objects.
// Every function below checks one reply against the §18 shape and returns
// typed values (BigInt for numbers); anything else REJECTS — a reply that
// does not have the documented shape is never shown as a value.
//
// Trust: every answer comes from ONE node's committed tip state (§18: "Hepsi
// düğüm-yerel"). A receipt's digest `dg` is re-computed here from the
// receipt fields (§7: SHA3-512 of the canonical encoding — the node's
// encoder is nodus_witness_rt_evm.c rcpt_build, Data = its SHA3-512,
// nodus_witness_v2_apply.c). That proves the fields and `dg` agree; binding
// `dg` to the chain needs the next block's LastResultsHash, which no RPC
// offers and this wallet does not read — so a receipt is shown as reported
// by the connected node (red-team 1 F11).
import { keccak_256, sha3_512 } from '@noble/hashes/sha3';
import { bytesToHex, hexToBytes } from './address.js';

const DEC = /^(0|[1-9]\d{0,77})$/;
const HEX = /^([0-9a-f]{2})*$/;
const U64 = 2n ** 64n, U32 = 2n ** 32n;

function bad(what) { return new Error(`The node's smart-contract answer is malformed (${what}).`); }
function num(v, what, limit = U64) {
  if (typeof v !== 'string' || !DEC.test(v)) throw bad(what);
  const n = BigInt(v);
  if (n >= limit) throw bad(what);
  return n;
}
function hex(v, what, bytes = null) {
  if (typeof v !== 'string' || !HEX.test(v) || (bytes !== null && v.length !== 2 * bytes)) throw bad(what);
  return v;
}
function map(v, what) { if (!v || typeof v !== 'object' || Array.isArray(v)) throw bad(what); return v; }
function list(v, what) { if (!Array.isArray(v)) throw bad(what); return v; }

export const EVM_LOGS_MAX = 1000;        // §18 evm_logs lim <= 1000
export const EVM_LOGS_SPAN = 10000;      // §18 evm_logs range <= 10 000 blocks

// keccak256("") — the code hash of an account without code (§18 evm_account
// "hesap yoksa ... ch=keccak("")").
export const EMPTY_CODE_HASH = bytesToHex(keccak_256(new Uint8Array(0)));

export function parseAccount(r) {
  map(r, 'account');
  return { nonce: num(r.n, 'nonce'), balanceWei: BigInt(`0x${hex(r.b, 'balance', 32)}`), codeHash: hex(r.ch, 'code hash', 32), codeSize: num(r.cs, 'code size', U32), height: num(r.h, 'height') };
}
export function parseCode(r) { map(r, 'code'); return { code: hex(r.c, 'code'), height: num(r.h, 'height') }; }
export function parseStorage(r) { map(r, 'storage'); return { value: hex(r.v, 'storage value', 32), height: num(r.h, 'height') }; }

export function parseCall(r) {
  map(r, 'call');
  const status = num(r.s, 'status', 256n);
  if (status > 1n) throw bad('status');
  return { success: status === 1n, output: hex(r.o, 'output'), gasUsed: num(r.gu, 'gas used'), height: num(r.h, 'height') };
}
export function parseEstimate(r) {
  const c = parseCall(r);
  return { ...c, gasLimit: num(r.ge, 'suggested gas'), units: num(r.ue, 'suggested resource ceiling'), fee: num(r.fe, 'suggested fee') };
}

function parseLogEntry(l, i) {
  map(l, `log ${i}`);
  const topics = list(l.t, `log ${i} topics`).map((t, k) => hex(t, `log ${i} topic ${k}`, 32));
  if (topics.length > 4) throw bad(`log ${i} topics`);
  return { address: hex(l.a, `log ${i} address`, 32), topics, data: hex(l.d, `log ${i} data`) };
}

// evm_receipt -> null (no receipt: {}) or the receipt with its digest
// re-checked. `height` is the reply's `h` = the height the item was
// INCLUDED at (design §18 rev 5: "evm_receipt ve evm_logs kayıtlarında h =
// öğenin DAHİL edildiği yükseklik (tip değil)"; `index` and `digest` are
// meaningful only for that block). status: 'applied-success' |
// 'applied-failed' (the item was applied, the fee paid, the nonce consumed
// — §4). Everything here is AS REPORTED BY THE CONNECTED NODE: the digest
// check proves the fields and `dg` agree, not that the chain committed
// them (red-team 1 F11); a deployment's `created` is checked against the
// signed transaction by src/evm/contract.js createdCheck.
export function parseReceipt(r) {
  map(r, 'receipt');
  if (Object.keys(r).length === 0) return null;
  const status = num(r.s, 'status', 256n);
  if (status > 1n) throw bad('status');
  const op = Number(num(r.op, 'op', 256n));
  if (op < 1 || op > 5) throw bad('op');
  const receipt = {
    height: num(r.h, 'height'), index: num(r.x, 'item index', U32), success: status === 1n, op,
    gasUsed: num(r.gu, 'gas used'), created: r.cr === undefined ? null : hex(r.cr, 'created address', 32),
    output: hex(r.o, 'output'), logs: list(r.logs, 'logs').map(parseLogEntry),
    weiDestroyed: BigInt(`0x${hex(r.wd, 'destroyed value', 32)}`),
    tickets: list(r.tk, 'tickets').map((t, i) => hex(t, `ticket ${i}`, 64)),
    digest: hex(r.dg, 'digest', 64)
  };
  if (receipt.created !== null && !(receipt.success && op === 2)) throw bad('created address');
  if (receipt.tickets.length > 0xffff) throw bad('tickets');
  if (receiptDigest(receipt) !== receipt.digest) throw new Error("The node's receipt does not match its own digest; it is not shown.");
  receipt.status = receipt.success ? 'applied-success' : 'applied-failed';
  return receipt;
}

// The §7 canonical receipt bytes (nodus_witness_rt_evm.c rcpt_build):
//   "NDS.EVMRCPT.v1\0\0" ‖ status u8 ‖ op u8 ‖ evm_gas_used u64 ‖ created[32]
//   ‖ output_len u32 ‖ output ‖ n_logs u32 ‖ n_logs × (addr[32] ‖ n_topics
//   u8 ‖ topics ‖ data_len u32 ‖ data) ‖ wei_destroyed[32] ‖ n_tickets u16
//   ‖ ticket ids (64 each)
export function receiptBytes(rc) {
  const parts = [];
  const tag = new Uint8Array(16);
  tag.set(new TextEncoder().encode('NDS.EVMRCPT.v1'));
  const be = (v, n) => { const b = new Uint8Array(n); let x = BigInt(v); for (let i = n - 1; i >= 0; i--) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };
  parts.push(tag, Uint8Array.of(rc.success ? 1 : 0, rc.op), be(rc.gasUsed, 8));
  parts.push(rc.created ? hexToBytes(rc.created) : new Uint8Array(32));
  const out = hexToBytes(rc.output);
  parts.push(be(out.length, 4), out, be(rc.logs.length, 4));
  for (const lg of rc.logs) {
    const data = hexToBytes(lg.data);
    parts.push(hexToBytes(lg.address), Uint8Array.of(lg.topics.length), ...lg.topics.map(hexToBytes), be(data.length, 4), data);
  }
  parts.push(be(rc.weiDestroyed, 32), be(rc.tickets.length, 2), ...rc.tickets.map(hexToBytes));
  const all = new Uint8Array(parts.reduce((s, p) => s + p.length, 0));
  let o = 0;
  for (const p of parts) { all.set(p, o); o += p.length; }
  return all;
}
export const receiptDigest = rc => bytesToHex(sha3_512(receiptBytes(rc)));

// (h, x, li) order: <0 / 0 / >0 (nodus_client.c evm_log_pos_cmp).
function posCmp(a, b) {
  for (const k of ['height', 'index', 'logIndex']) if (a[k] !== b[k]) return a[k] < b[k] ? -1 : 1;
  return 0;
}

// evm_logs -> { logs: [{ height, index, logIndex, address, topics, data,
// intentId }], more, cursor } (red-team 1 F4: the node scans a bounded
// number of rows from the request's start, so `more` means "the scan
// stopped before th" and such a page may hold ZERO logs; `cursor` =
// { height, index, logIndex } — the first position the node has not
// examined, to send back as the next request's cursor (decimal strings) —
// present exactly when more, null otherwise).
// The page is taken exactly when the C SDK takes it (nodus_client.c
// evm_dec_logs + evm_logs_page_check): "c" = [h, x, li] with x / li <= 2^32
// (nodus.h NODUS_EVM_LOGS_CURSOR_POS_MAX) present exactly when more; logs
// strictly increasing in (h, x, li); the cursor strictly after the last
// log. Against `q`, the tagged request (src/nodus/client.js evmArgs; given
// by evmRead): at most `lim` logs, each inside [fh, th] and not before the
// start (the request's cursor, else (fh, 0, 0)); the cursor inside
// [fh, th] and not behind the start.
export function parseLogs(r, q = null) {
  map(r, 'logs');
  const logs = list(r.logs, 'logs').map((l, i) => ({
    ...parseLogEntry(l, i), height: num(l.h, `log ${i} height`), index: num(l.x, `log ${i} item`, U32),
    logIndex: num(l.li, `log ${i} position`, U32), intentId: hex(l.i, `log ${i} transaction`, 64)
  }));
  if (logs.length > EVM_LOGS_MAX || typeof r.more !== 'boolean') throw bad('logs');
  if ((r.c !== undefined) !== r.more) throw bad('cursor present exactly when more');
  let cursor = null;
  if (r.c !== undefined) {
    const c = list(r.c, 'cursor');
    if (c.length !== 3) throw bad('cursor');
    cursor = { height: num(c[0], 'cursor'), index: num(c[1], 'cursor', U32 + 1n), logIndex: num(c[2], 'cursor', U32 + 1n) };
  }
  for (let i = 1; i < logs.length; i++) if (posCmp(logs[i - 1], logs[i]) >= 0) throw bad('log order');
  if (cursor && logs.length > 0 && posCmp(logs[logs.length - 1], cursor) >= 0) throw bad('cursor behind the last log');
  if (q) {
    const fh = BigInt(q.fh[1]), th = BigInt(q.th[1]);
    const start = q.c ? { height: BigInt(q.c[1][0]), index: BigInt(q.c[1][1]), logIndex: BigInt(q.c[1][2]) } : { height: fh, index: 0n, logIndex: 0n };
    if (BigInt(logs.length) > BigInt(q.lim[1])) throw bad('logs over the limit');
    for (const l of logs) if (l.height < fh || l.height > th || posCmp(l, start) < 0) throw bad('log outside the requested range');
    if (cursor && (cursor.height < fh || cursor.height > th || posCmp(cursor, start) < 0)) throw bad('cursor outside the requested range');
  }
  return { logs, more: r.more, cursor };
}

// evm_ticket -> { pending, amountRaw, dest }
export function parseTicket(r) {
  map(r, 'ticket');
  if (typeof r.p !== 'boolean') throw bad('ticket state');
  return { pending: r.p, amountRaw: num(r.amt, 'ticket amount'), dest: hex(r.dst, 'ticket destination', 64) };
}
