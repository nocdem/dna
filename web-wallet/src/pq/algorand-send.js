// Canonical native-payment primitives. Signing and reviewed submission live
// in algorand-payment-sign.js and algorand-transfer.js. These functions alone
// neither sign nor submit; the controller enforces verified network/account rules.
// https://dev.algorand.co/concepts/transactions/reference/
// https://dev.algorand.co/concepts/transactions/fees/
const MAX = (1n << 64n) - 1n;
const enc = new TextEncoder();
function uint(v) {
  if (typeof v === 'number' && !Number.isSafeInteger(v)) throw new Error('Unsafe integer');
  if (!['string', 'number', 'bigint'].includes(typeof v) || !/^(0|[1-9][0-9]*)$/.test(String(v))) throw new Error('Invalid uint64');
  const n = BigInt(v); if (n > MAX) throw new Error('Invalid uint64'); return n;
}
function concat(...parts) { const a = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let i = 0; for (const p of parts) { a.set(p, i); i += p.length; } return a; }
function num(v) {
  v = uint(v);
  if (v < 128n) return Uint8Array.of(Number(v));
  const size = v <= 255n ? 1 : v <= 65535n ? 2 : v <= 4294967295n ? 4 : 8;
  const out = new Uint8Array(1 + size); out[0] = ({1:204,2:205,4:206,8:207})[size];
  for (let i = size; i > 0; i--) { out[i] = Number(v & 255n); v >>= 8n; } return out;
}
function str(v) { const b = enc.encode(v); if (b.length > 31) throw new Error('String too long'); return concat(Uint8Array.of(0xa0 + b.length), b); }
function bin(v, length) { if (!(v instanceof Uint8Array) || v.length !== length) throw new Error('Invalid byte field'); return concat(Uint8Array.of(0xc4, v.length), v); }
/** Serialize a single unsigned payment; byte addresses are 32-byte decoded addresses.
 * The caller must validate checksums, network identity and account authorization.
 */
export function encodeAlgorandPayment({sender, receiver, amount, fee, firstValid, lastValid, genesisHash, genesisId}) {
  const fields = [];
  const addNum = (key, val) => { const n = uint(val); if (n) fields.push([key, num(n)]); return n; };
  const amountN = addNum('amt', amount); const feeN = addNum('fee', fee);
  const fv = addNum('fv', firstValid), lv = uint(lastValid);
  if (!amountN || !feeN || !fv || lv < fv || lv - fv > 1000n) throw new Error('Invalid payment parameters');
  if (typeof genesisId !== 'string' || !/^[\x21-\x7e]{1,31}$/.test(genesisId)) throw new Error('Invalid genesis ID');
  fields.push(['gen', str(genesisId)], ['gh', bin(genesisHash, 32)], ['lv', num(lv)], ['rcv', bin(receiver, 32)], ['snd', bin(sender, 32)], ['type', str('pay')]);
  fields.sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
  return concat(Uint8Array.of(0x80 + fields.length), ...fields.flatMap(([k,v]) => [str(k),v]));
}
/** Conservative quote only; size must cover the entire signed envelope, not just the transaction. */
export function quoteAlgorandFalconFee({minFee, feePerByte, signedSize, maxFee}) {
  const min = uint(minFee), perByte = uint(feePerByte), size = uint(signedSize), cap = uint(maxFee);
  if (!min || !size) throw new Error('Invalid fee parameters');
  const floor = min * 3n, congested = perByte * size;
  const result = floor > congested ? floor : congested;
  if (result > MAX || result > cap) throw new Error('Fee exceeds limit');
  return result;
}
/** Require enough balance after payment and fee to meet the node-reported minimum. */
export function checkAlgorandSpend({balance, minimumBalance, amount, fee}) {
  const b = uint(balance), minimum = uint(minimumBalance), a = uint(amount), f = uint(fee);
  if (!a || !f || a + f + minimum > b) throw new Error('Insufficient spendable balance');
  return true;
}

/** Native Falcon signs HashRep(txn): ASCII TX followed by the canonical raw
 * transaction bytes, not the SHA-512/256 transaction ID. Only constructed
 * payment fields are accepted, avoiding an arbitrary-data signing interface.
 * See go-algorand v5.0.0-stable data/transactions/pqsig_test.go,
 * data/transactions/transaction.go and protocol/hash.go.
 */
export function algorandFalconPaymentPreimage(payment) {
  return concat(Uint8Array.of(0x54, 0x58), encodeAlgorandPayment(payment));
}
