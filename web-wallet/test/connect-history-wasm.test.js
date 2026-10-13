// Nodus Connect history records through the REAL module (BUGS W-15, web
// 0.1.112). Since 0.1.112 a record's bytes cross into nc_hist_encrypt /
// nc_hist_decrypt through the heap input buffer (nc_group_in_alloc) instead of
// a hex argument that Emscripten copied onto the 1 MiB C stack, so a record
// may be up to 1 MiB (NC_HIST_PT_MAX) instead of 64 KiB.
//
// What this proves, on the release build of this tree:
//   - a 200 KB record (over the old 64 KiB cap) seals and opens, byte for byte;
//   - a ciphertext with one bit flipped, or another record id, does not open;
//   - 1 MiB + 1 byte is refused by the buffer;
//   - (with NODUS_CONNECT_OLD_OUT) a record SEALED BY THE PREVIOUS RELEASE's
//     module (hex argument, 0.1.111) OPENS with this one — the records already
//     kept on users' devices stay readable (same key, AAD and layout).
// Requires: NODUS_SEND_PARITY_OUT (scripts/build-nodus-send-wasm.sh parity on
// this tree); optional NODUS_CONNECT_OLD_OUT (the same build of 0.1.111).
// Skips without NODUS_SEND_PARITY_OUT (a skip is not a pass).
import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { nodusSigningSeed } from '../src/nodus/derive.js';
import { normalizePhrase } from '../src/recovery.js';
import { NODUS_SEND_NETWORK } from '../src/nodus/send-module.js';

const NEW = process.env.NODUS_SEND_PARITY_OUT, OLD = process.env.NODUS_CONNECT_OLD_OUT;
const PHRASE = normalizePhrase('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art');
const VAULT = '07'.repeat(16), STORE = 'state', ID = 'state';
const hex = bytes => Buffer.from(bytes).toString('hex');

async function opened(dir) {
  const { default: create } = await import(pathToFileURL(join(dir, 'send-node.mjs')).href);
  const M = await create();
  const fail = what => new Error(`${what}: ${M.ccall('nc_error', 'string', [], []) || M.ccall('nsw_error', 'string', [], [])}`);
  // identify wants the network settings present (nsw_identify_core); nothing
  // connects here — the history calls are local.
  const net = NODUS_SEND_NETWORK, rc = [
    M.ccall('nsw_net_reset', 'number', [], []),
    M.ccall('nsw_net_set_chain', 'number', ['string'], [net.chainId]),
    M.ccall('nsw_net_add_endpoint', 'number', ['string', 'number'], [net.endpoints[0].host, net.endpoints[0].port]),
    ...net.pins.map(pin => M.ccall('nsw_net_add_pin', 'number', ['string'], [pin]))
  ];
  if (rc.some(r => r !== 0)) throw fail('network settings');
  M.HEAPU8.set(nodusSigningSeed(PHRASE), M.ccall('nsw_seed_buf', 'number', [], []));
  if (await M.ccall('nsw_identify', 'number', [], [], { async: true }) !== 0) throw fail('identify');
  const words = new TextEncoder().encode(PHRASE);
  M.HEAPU8.set(words, M.ccall('nc_words_alloc', 'number', ['number'], [words.length]));
  if (await M.ccall('nc_unlock', 'number', ['number'], [0], { async: true }) !== 0) throw fail('unlock');
  if (M.ccall('nc_hist_key', 'number', ['string'], [VAULT]) !== 0) throw fail('history key');
  const result = () => JSON.parse(M.ccall('nc_result', 'string', [], []));
  const putIn = bytes => {
    const at = M.ccall('nc_group_in_alloc', 'number', ['number'], [bytes.length]);
    if (at) M.HEAPU8.set(bytes, at);
    return at;
  };
  return { M, result, putIn, fail };
}

// 0.1.112 and later: bytes through the heap input buffer.
function seal(m, plaintext, counter = '0', id = ID) {
  assert.ok(m.putIn(plaintext), 'the buffer takes the record');
  if (m.M.ccall('nc_hist_encrypt', 'number', ['string', 'string', 'string'], [STORE, id, counter]) !== 0) throw m.fail('seal');
  return m.result();
}
function open(m, sealed, id = ID) {
  assert.ok(m.putIn(Buffer.from(sealed.ct, 'hex')), 'the buffer takes the record');
  const rc = m.M.ccall('nc_hist_decrypt', 'number', ['string', 'string', 'string', 'string'], [STORE, id, sealed.nonce, sealed.tag]);
  return rc === 0 ? m.result().pt : null;
}

const skip = NEW ? false : 'set NODUS_SEND_PARITY_OUT (scripts/build-nodus-send-wasm.sh parity on this tree)';

test('history (W-15): a 200 KB record — over the old 64 KiB cap — seals and opens through the heap buffer', { skip }, async () => {
  const m = await opened(NEW);
  const plaintext = new Uint8Array(200 * 1024).map((_, i) => (i * 31 + 7) & 0xff);
  const sealed = seal(m, plaintext, '41');
  assert.equal(sealed.counter, '42');
  assert.equal(sealed.ct.length, plaintext.length * 2);
  assert.equal(open(m, sealed), hex(plaintext));
  // One flipped bit, or another record id (the AAD), does not open.
  const flipped = Buffer.from(sealed.ct, 'hex'); flipped[1000] ^= 1;
  assert.equal(open(m, { ...sealed, ct: flipped.toString('hex') }), null);
  assert.equal(open(m, sealed, 'p00000000000000000001'), null);
  // The cap: 1 MiB fits the buffer, 1 MiB + 1 does not.
  assert.ok(m.putIn(new Uint8Array(1048576).fill(1)));
  assert.equal(m.putIn(new Uint8Array(1048577).fill(1)), 0);
  // The buffer is consumed by the call: a second call without it is refused.
  m.putIn(new Uint8Array(0));
  assert.notEqual(m.M.ccall('nc_hist_encrypt', 'number', ['string', 'string', 'string'], [STORE, ID, '1']), 0);
});

test('history (W-15): a record sealed by the 0.1.111 module (hex argument) opens with this one', { skip: skip || (OLD ? false : 'set NODUS_CONNECT_OLD_OUT (the parity build of 0.1.111)') }, async () => {
  const old = await opened(OLD), now = await opened(NEW);
  const plaintext = new TextEncoder().encode(JSON.stringify({ version: 1, nextSeq: '7', contacts: [] }));
  // 0.1.111: nc_hist_encrypt(store, id, pt_hex, counter)
  assert.equal(old.M.ccall('nc_hist_encrypt', 'number', ['string', 'string', 'string', 'string'], [STORE, ID, hex(plaintext), '5']), 0, 'the old module seals');
  const sealed = old.result();
  assert.equal(open(now, sealed), hex(plaintext));
});
