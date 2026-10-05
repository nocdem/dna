// Smart contracts (the Nodus EVM domain) — value units.
//
// Design docs/plans/2026-10-04-nodus-evm-chain-integration-design.md rev 3 §5:
// q = 10^10 — one raw NODUS unit is 10^10 EVM units (wei), so with NODUS's 8
// decimals "1 ether" inside the EVM equals 1 NODUS (operator decision
// 2026-10-04-nodus-evm-kurultay-k1.md #3). A withdrawal leaves the EVM in whole raw
// units only: there is no rounding, a fraction below 10^10 wei stays in the
// EVM (same decision).
//
// Everything here is BigInt; Number is never used for an amount.

export const WEI_PER_RAW = 10n ** 10n;
export const EVM_DECIMALS = 18;
export const NODUS_DECIMALS = 8;
const U256_MAX = 2n ** 256n - 1n;
const U64_MAX = 2n ** 64n - 1n;

function big(value, what) {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'string' && /^(0|[1-9]\d*)$/.test(value)) return BigInt(value);
  throw new Error(`Invalid ${what}.`);
}

// raw NODUS units (bigint or decimal string) -> wei (bigint)
export function rawToWei(raw) {
  const r = big(raw, 'amount');
  if (r < 0n || r > U64_MAX) throw new Error('Amount is out of range.');
  return r * WEI_PER_RAW;
}

// wei -> { raw, rest }: the whole raw units a withdrawal can move and the
// remainder that stays in the EVM (never rounded).
export function weiToRaw(wei) {
  const w = big(wei, 'amount');
  if (w < 0n || w > U256_MAX) throw new Error('Amount is out of range.');
  return { raw: w / WEI_PER_RAW, rest: w % WEI_PER_RAW };
}

// A non-negative integer as a decimal with `decimals` places, trailing
// zeros removed ("1.5", "0.000000000000000001", "12").
export function formatUnits(value, decimals) {
  const v = big(value, 'amount');
  if (v < 0n) throw new Error('Amount is out of range.');
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 77) throw new Error('Invalid decimals.');
  const base = 10n ** BigInt(decimals);
  const whole = v / base, frac = v % base;
  if (frac === 0n) return whole.toString();
  return `${whole}.${frac.toString().padStart(decimals, '0').replace(/0+$/, '')}`;
}

// A decimal text ("1", "0.25") with at most `decimals` places -> integer.
// Refuses signs, exponents, separators and more places than allowed.
export function parseUnits(text, decimals) {
  if (typeof text !== 'string') throw new Error('Enter an amount.');
  const t = text.trim();
  if (!/^(0|[1-9]\d*)(\.\d+)?$/.test(t)) throw new Error('Enter an amount as a number, for example 1.5.');
  const [whole, frac = ''] = t.split('.');
  if (frac.length > decimals) throw new Error(`At most ${decimals} decimal places.`);
  return BigInt(whole) * 10n ** BigInt(decimals) + (decimals ? BigInt(frac.padEnd(decimals, '0')) : 0n);
}

export const formatWei = wei => formatUnits(wei, EVM_DECIMALS);
export const parseWei = text => { const w = parseUnits(text, EVM_DECIMALS); if (w > U256_MAX) throw new Error('Amount is out of range.'); return w; };
export const formatRaw = raw => formatUnits(raw, NODUS_DECIMALS);
export const parseRaw = text => { const r = parseUnits(text, NODUS_DECIMALS); if (r > U64_MAX) throw new Error('Amount is out of range.'); return r; };

// wei <-> the 32-byte big-endian word the call bytes carry (64 lowercase hex)
export function weiToWord(wei) {
  const w = big(wei, 'amount');
  if (w < 0n || w > U256_MAX) throw new Error('Amount is out of range.');
  return w.toString(16).padStart(64, '0');
}
export function wordToWei(hex) {
  if (typeof hex !== 'string' || !/^[0-9a-f]{64}$/.test(hex)) throw new Error('Invalid amount word.');
  return BigInt(`0x${hex}`);
}
