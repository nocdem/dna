// Pure logic of the swap site: units, the minimum to receive, request bodies, the signed texts, the
// typed data, plain-word refusals and swap states. No DOM, no network, no extension: testable with
// `node --test`. Every amount is a BigInt of raw units (plan section 5: USDT 6 decimals, NODUS 8).
//
// Plan: /opt/dna/docs/plans/2026-11-08-swap-bot-plan.nodus1.md (revision 12), cited by section.
// Nothing here checks, verifies or signs the bot's answers (givens item 69: the site is the bot's own screen).

export const USDT_DECIMALS = 6;
export const NODUS_DECIMALS = 8;
export const U64_MAX = (1n << 64n) - 1n;
// Fallback only (plan section 14 "Smallest add", givens item 96): the default of the bot's setting
// `liquidity_min_nodus`, 100,000 NODUS. GET /amm/status "settings.liquidityMinNodus" is what the page shows and
// checks (`liquidityMinNodusRaw`); this constant is used only when that field is absent or not a canonical number.
// The bot's own "below_minimum" refusal still governs.
export const LIQUIDITY_MIN_NODUS_RAW = 100000n * 10n ** 8n;

// The add minimum in raw NODUS units: the status value when it is a canonical decimal string (digits, no leading
// zero, at most 2^64 - 1, parsed with BigInt), else the fallback constant.
export function liquidityMinNodusRaw(status) {
  const v = status?.settings?.liquidityMinNodus;
  if (typeof v === 'string' && /^(0|[1-9]\d*)$/.test(v)) {
    const raw = BigInt(v);
    if (raw <= U64_MAX) return raw;
  }
  return LIQUIDITY_MIN_NODUS_RAW;
}
// "100,000" for display: the whole NODUS part with commas, the fraction only when there is one.
export function nodusWithCommas(raw) {
  const [i, f] = formatFixed(raw, NODUS_DECIMALS).split('.');
  const frac = f.replace(/0+$/, '');
  return `${i.replace(/\B(?=(\d{3})+(?!\d))/g, ',')}${frac ? `.${frac}` : ''}`;
}
// The USDT contract address the extension needs as `token`: only "0x" + 40 hex counts.
export const isTokenAddress = v => typeof v === 'string' && /^0x[0-9a-fA-F]{40}$/.test(v);

const DIGITS = /^\d+$/;
const pow10 = n => 10n ** BigInt(n);

// ── amounts ─────────────────────────────────────────────────────────────

// "100", "0.5", ".5", "5." -> raw units. Refuses more fraction digits than the token has (plan 6.4.2), zero, and
// anything above 2^64 - 1 (the bot reads amounts as u64, amm_http.c dec_u64).
export function parseAmount(text, decimals) {
  const t = String(text ?? '').trim();
  if (t === '') return { ok: false, reason: 'empty' };
  const m = /^(\d*)(?:\.(\d*))?$/.exec(t);
  if (!m || (m[1] === '' && (m[2] ?? '') === '')) return { ok: false, reason: 'format' };
  const frac = m[2] ?? '';
  if (frac.length > decimals) return { ok: false, reason: 'too_many_decimals' };
  const raw = BigInt(m[1] || '0') * pow10(decimals) + BigInt(frac.padEnd(decimals, '0') || '0');
  if (raw === 0n) return { ok: false, reason: 'zero' };
  if (raw > U64_MAX) return { ok: false, reason: 'too_large' };
  return { ok: true, raw };
}

// Plan 6.4.2 value form: `<integer>.<exactly decimals digits>`; the integer part has no leading zero.
export function formatFixed(raw, decimals) {
  const r = toBig(raw);
  const s = r.toString().padStart(decimals + 1, '0');
  return `${s.slice(0, s.length - decimals)}.${s.slice(s.length - decimals)}`;
}
export const usdtText = raw => `${formatFixed(raw, USDT_DECIMALS)} USDT`;
export const nodusText = raw => `${formatFixed(raw, NODUS_DECIMALS)} NODUS`;

// Screen form: trailing fraction zeros dropped ("100", "1248.6").
export function displayAmount(raw, decimals) {
  const [i, f] = formatFixed(raw, decimals).split('.');
  const frac = f.replace(/0+$/, '');
  return frac ? `${i}.${frac}` : i;
}

export function toBig(value) {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'string' && /^\d+$/.test(value)) return BigInt(value);
  throw new TypeError('A raw amount must be a BigInt or a string of digits.');
}

// Tolerance typed as a percentage ("0.5") -> basis points (50). 0..100 %, at most 2 fraction digits.
export function percentToBps(text) {
  const t = String(text ?? '').trim();
  const m = /^(\d{1,3})(?:\.(\d{1,2}))?$/.exec(t);
  if (!m) return { ok: false, reason: 'format' };
  const bps = Number(m[1]) * 100 + Number((m[2] ?? '').padEnd(2, '0') || '0');
  if (bps > 10000) return { ok: false, reason: 'too_large' };
  return { ok: true, bps };
}

// Whether an approve button may be pressed: no approval sequence runs, a quote is held, the tolerance is usable (the
// add has none: it passes true) and the extension accounts are connected. One rule for both approve buttons (swap.js).
export const approveEnabled = ({ busy, quote, toleranceOk, accounts }) => !busy && Boolean(quote) && toleranceOk === true && Boolean(accounts);

// ── the minimum to receive ──────────────────────────────────────────────

// Plan section 7 step 4 (lines 444, repeated for the other direction in section 8 step 4, line 465; operator's
// answer givens item 82, question 2 option c, "Kullanıcı sitede yüzdeyi kendisi seçer."): the site computes the
// minimum before the user signs, as THORChain computes a quote's limit,
//   (number - estimated network fee) x (10000 - the user's tolerance in basis points) / 10000, truncated,
// "with the estimated fee the answer shows (item 82) and the subtraction saturating (section 5)". The number and
// the estimated fee are the bot's answer, in the output's unit (NODUS raw for USDT -> NODUS, USDT raw for
// NODUS -> USDT). The plan's reading differs from main's earlier note "the number less a tolerance": the fee is
// taken off first, so a tolerance of 0 does not refund at an unchanged price (plan line 444).
export function minimumToReceive(number, estimatedFee, toleranceBps) {
  if (!Number.isInteger(toleranceBps) || toleranceBps < 0 || toleranceBps > 10000) {
    throw new RangeError('The tolerance must be a whole number of basis points from 0 to 10000.');
  }
  const n = toBig(number), fee = toBig(estimatedFee);
  const net = n > fee ? n - fee : 0n;               // saturating subtraction, plan section 5
  return net * BigInt(10000 - toleranceBps) / 10000n; // BigInt division truncates, as THORChain's QuoUint64
}

// ── the price from /amm/status ──────────────────────────────────────────

// Indicative pool price from the two reserves (strings of raw units; "above_2_64" when a side does not fit u64,
// amm_http.c u256_dec; `reserves` is null when no pool exists yet). The bot's number for the chosen amount is
// what counts; this only shows "the price" of plan section 7 step 1.
export function priceFromReserves(reserves) {
  if (!reserves || !/^\d+$/.test(reserves.nodus ?? '') || !/^\d+$/.test(reserves.usdt ?? '')) return null;
  const n = BigInt(reserves.nodus), u = BigInt(reserves.usdt);
  if (n === 0n || u === 0n) return null;
  // NODUS per USDT = (n / 10^8) / (u / 10^6) = n / (100 u); four fraction digits: n * 100 / u in units of 10^-4.
  const nodusPerUsdt = n * 100n / u;
  // USDT per NODUS = u * 100 / n; six fraction digits: u * 10^8 / n in units of 10^-6.
  const usdtPerNodus = u * 100000000n / n;
  return {
    nodusPerUsdt: displayAmount(nodusPerUsdt, 4),
    usdtPerNodus: displayAmount(usdtPerNodus, 6),
  };
}

// What the pool holds, for the "Pool" line: "<USDT> USDT · <NODUS> NODUS". `reserves` is null when no pool exists yet;
// a side that does not fit u64 arrives as "above_2_64" and is not shown as a number.
export function poolText(reserves) {
  if (!reserves) return 'Empty, no liquidity yet';
  if (!DIGITS.test(reserves.usdt ?? '') || !DIGITS.test(reserves.nodus ?? '')) return 'Too large to show';
  return `${displayAmount(BigInt(reserves.usdt), USDT_DECIMALS)} USDT · ${nodusWithCommas(BigInt(reserves.nodus))} NODUS`;
}

// How far the bot's rate for this amount (number / amount, raw units both) is below the pool price from the same
// reserves, as a percentage with two decimals, truncated: "0.03", "50.00". With a the amount in, out the number the
// bot gives, rIn and rOut the pool's reserves of the input and output side, the pool price is rOut / rIn and
//   movement = 1 - (out / a) / (rOut / rIn) = (a x rOut - out x rIn) / (a x rOut).
// A bot rate at or above the pool price gives "0.00" (never negative). null when the pool price is unknown (no
// pool, "above_2_64", an empty side) or an input is unusable.
export function priceMovementPercent(reserves, direction, amountRaw, numberRaw) {
  if (direction !== 'usdt_to_nodus' && direction !== 'nodus_to_usdt') return null;
  if (!reserves || !DIGITS.test(reserves.usdt ?? '') || !DIGITS.test(reserves.nodus ?? '')) return null;
  let a, out;
  try { a = toBig(amountRaw); out = toBig(numberRaw); } catch { return null; }
  const u = BigInt(reserves.usdt), n = BigInt(reserves.nodus);
  if (u === 0n || n === 0n || a <= 0n || out < 0n) return null;
  const [rIn, rOut] = direction === 'usdt_to_nodus' ? [u, n] : [n, u];
  const whole = a * rOut, lost = whole - out * rIn;
  const hundredths = lost > 0n ? lost * 10000n / whole : 0n;   // percent x 100, truncated
  return formatFixed(hundredths, 2);
}

// Ethereum blocks the bot waits before it counts a USDT payment, by amount (the bot's defaults, amm_cfg.c
// amm_cfg_defaults eth_conf_*; amm_cfg.h: "up to and including bound 1 waits count 1, up to and including bound 2
// waits count 2, above bound 2 waits count 3"). /amm/status does not carry these, so they are constants here.
// `usdtRaw` is a BigInt or a string of digits; null for empty, zero or anything unusable.
export function ethConfirmations(usdtRaw) {
  let v;
  try { v = toBig(usdtRaw); } catch { return null; }
  if (v <= 0n) return null;
  return v <= 100000000n ? 3n : v <= 1000000000n ? 5n : 33n;
}

// Ethereum blocks the bot waits after a USDT payout before it marks the swap "paid": payout_final_depth_eth (the bot's
// setting, amm_cfg.c:50, meaning amm_cfg.h:73, enforced in amm_eth_pay.c:217: the Ethereum tip at least this many blocks
// above the payout receipt's block). The live value is 3 (the bot's /etc/nodus-amm.conf `payout_final_depth_eth = 3`, set from 64 to 3 on the operator's word at 2026-11-11T23:47Z);
// /amm/status does not carry it, so it is a constant here, like the confirmation tiers above. At Sepolia's 12 s per
// block 3 blocks are about 36 seconds. A NODUS payout has no such wait: the bot marks it paid when its transaction is
// confirmed in a Nodus block (amm_nodus_pay.c finish_confirmed), so no number is shown for it.
export const PAYOUT_FINAL_DEPTH_ETH = 3;
export const PAYOUT_FINAL_SECONDS_ETH = 36;

// The "Payment counted after" value for the typed amount (text) and the direction. NODUS -> USDT: a
// committed Nodus block needs no extra depth (amm_nodus_watch.c). "—" for an empty or unusable amount.
export function waitText(direction, amountText) {
  const decimals = direction === 'usdt_to_nodus' ? USDT_DECIMALS : NODUS_DECIMALS;
  const p = parseAmount(amountText, decimals);
  if (!p.ok) return '—';
  if (direction !== 'usdt_to_nodus') return '1 Nodus block';
  return `${ethConfirmations(p.raw)} Ethereum blocks`;
}

// ── request bodies the site itself posts (plan 6.4.7; amm_http.c) ───────

const hexOfText = text => Array.from(new TextEncoder().encode(text), b => b.toString(16).padStart(2, '0')).join('');

// POST /amm/quote: exactly two keys, both strings (amm_http.c route_quote refuses anything else).
export function quoteBody(direction, rawAmount) {
  if (direction !== 'usdt_to_nodus' && direction !== 'nodus_to_usdt') throw new RangeError('Unknown direction.');
  return JSON.stringify({ direction, amount: toBig(rawAmount).toString() });
}
// POST /amm/liquidity/quote: the amount of ONE side (amm_http.h).
export function liquidityQuoteBody(side, rawAmount) {
  if (side !== 'usdt' && side !== 'nodus') throw new RangeError('Unknown side.');
  return JSON.stringify({ side, amount: toBig(rawAmount).toString() });
}
// POST /amm/liquidity/withdraw: {"text":"0x<hex of the text bytes>","publicKey":"0x..","signature":"0x.."} (plan 6.4.7).
export function withdrawBody({ text, publicKey, signature }) {
  return JSON.stringify({ text: `0x${hexOfText(text)}`, publicKey, signature });
}
export { hexOfText };

// ── value forms of the signed texts (plan 6.4.2) ────────────────────────

const RE_ETH = /^0x[0-9a-f]{40}$/;
const RE_HEX128 = /^[0-9a-f]{128}$/;
const RE_HEX64 = /^[0-9a-f]{64}$/;
const RE_DEC_U64 = /^(0|[1-9]\d*)$/;
function need(re, value, name) {
  if (typeof value !== 'string' || !re.test(value)) throw new TypeError(`${name} has the wrong form.`);
  return value;
}
function needU64(value, name) {
  need(RE_DEC_U64, value, name);
  if (BigInt(value) > U64_MAX) throw new RangeError(`${name} is above 2^64 - 1.`);
  return value;
}
function needRaw(value, name) {
  const r = toBig(value);
  if (r > U64_MAX) throw new RangeError(`${name} is above 2^64 - 1.`);
  return r;
}

// A random request number for a request the bot does not number (the withdraw: no price question, plan 6.4.2
// "drawn at random by the site"; the bot refuses a reused one). Decimal, <= 2^64 - 1.
export function randomRequestNumber(getRandomValues = globalThis.crypto.getRandomValues.bind(globalThis.crypto)) {
  const bytes = getRandomValues(new Uint8Array(8));
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v.toString();
}

// ── the Nodus-key texts (plan 6.4.4 and 6.4.6): LF between lines, no trailing LF, fixed key order ──

// NODUS -> USDT request, plan 6.4.4. `minimumUsdtRaw` is the USDT minimum, `amountNodusRaw` the NODUS sent.
export function buildNodusToUsdtText({ sender, destination, amountNodusRaw, minimumUsdtRaw, transferId, chainId, requestNumber }) {
  return [
    'Nodus Swap: NODUS to USDT request',
    `Sender: ${need(RE_HEX128, sender, 'Sender')}`,
    `Destination: ${need(RE_ETH, destination, 'Destination')}`,
    `Amount: ${nodusText(needRaw(amountNodusRaw, 'Amount'))}`,
    `Minimum To Receive: ${usdtText(needRaw(minimumUsdtRaw, 'Minimum To Receive'))}`,
    `Transfer ID: ${need(RE_HEX128, transferId, 'Transfer ID')}`,
    `Chain ID: ${need(RE_HEX64, chainId, 'Chain ID')}`,
    `Request Number: ${needU64(requestNumber, 'Request Number')}`,
  ].join('\n');
}

// Liquidity add, Nodus half, plan 6.4.6.
export function buildLiquidityAddText({ ethereumAddress, nodusAddress, usdtAmountRaw, nodusAmountRaw, transferId, chainId, requestNumber }) {
  return [
    'Nodus Swap: liquidity add request',
    `Ethereum Address: ${need(RE_ETH, ethereumAddress, 'Ethereum Address')}`,
    `Nodus Address: ${need(RE_HEX128, nodusAddress, 'Nodus Address')}`,
    `USDT Amount: ${usdtText(needRaw(usdtAmountRaw, 'USDT Amount'))}`,
    `NODUS Amount: ${nodusText(needRaw(nodusAmountRaw, 'NODUS Amount'))}`,
    `Transfer ID: ${need(RE_HEX128, transferId, 'Transfer ID')}`,
    `Chain ID: ${need(RE_HEX64, chainId, 'Chain ID')}`,
    `Request Number: ${needU64(requestNumber, 'Request Number')}`,
  ].join('\n');
}

// Liquidity withdraw, plan 6.4.6 (signed by the Nodus key only, PROPOSED there, agreed 2026-11-10, givens item 71).
export function buildWithdrawText({ ethereumAddress, nodusAddress, basisPoints, chainId, requestNumber }) {
  if (!Number.isInteger(basisPoints) || basisPoints < 1 || basisPoints > 10000) {
    throw new RangeError('Basis points must be a whole number from 1 to 10000.');
  }
  return [
    'Nodus Swap: liquidity withdraw request',
    `Ethereum Address: ${need(RE_ETH, ethereumAddress, 'Ethereum Address')}`,
    `Nodus Address: ${need(RE_HEX128, nodusAddress, 'Nodus Address')}`,
    `Basis Points: ${basisPoints}`,
    `Chain ID: ${need(RE_HEX64, chainId, 'Chain ID')}`,
    `Request Number: ${needU64(requestNumber, 'Request Number')}`,
  ].join('\n');
}

// ── the typed data for eth_signTypedData_v4 (plan 6.4.3 and 6.4.6) ──────

function domainOf(domainName, chainId) {
  const id = Number(chainId);
  if (typeof domainName !== 'string' || domainName === '' || !Number.isSafeInteger(id) || id < 1) {
    throw new TypeError('The domain needs the bot\'s eip712Name and ethChainId from /amm/status.');
  }
  return { name: domainName, chainId: id };
}
const DOMAIN_TYPE = [{ name: 'name', type: 'string' }, { name: 'chainId', type: 'uint256' }];

// USDT -> NODUS request, plan 6.4.3. Amounts and the request number are decimal strings.
export function buildUsdtToNodusTypedData({ domainName, chainId, sender, destination, amountUsdtRaw, minimumNodusRaw, requestNumber }) {
  return {
    types: {
      EIP712Domain: DOMAIN_TYPE,
      UsdtToNodusRequest: [
        { name: 'sender', type: 'address' },
        { name: 'destination', type: 'string' },
        { name: 'amount', type: 'uint256' },
        { name: 'minimumToReceive', type: 'uint256' },
        { name: 'requestNumber', type: 'uint256' },
      ],
    },
    primaryType: 'UsdtToNodusRequest',
    domain: domainOf(domainName, chainId),
    message: {
      sender: need(RE_ETH, sender, 'sender'),
      destination: need(RE_HEX128, destination, 'destination'),
      amount: needRaw(amountUsdtRaw, 'amount').toString(),
      minimumToReceive: needRaw(minimumNodusRaw, 'minimumToReceive').toString(),
      requestNumber: needU64(requestNumber, 'requestNumber'),
    },
  };
}

// Liquidity add, Ethereum half, plan 6.4.6.
export function buildLiquidityAddTypedData({ domainName, chainId, ethereumAddress, nodusAddress, usdtAmountRaw, nodusAmountRaw, requestNumber }) {
  return {
    types: {
      EIP712Domain: DOMAIN_TYPE,
      LiquidityAddRequest: [
        { name: 'ethereumAddress', type: 'address' },
        { name: 'nodusAddress', type: 'string' },
        { name: 'usdtAmount', type: 'uint256' },
        { name: 'nodusAmount', type: 'uint256' },
        { name: 'requestNumber', type: 'uint256' },
      ],
    },
    primaryType: 'LiquidityAddRequest',
    domain: domainOf(domainName, chainId),
    message: {
      ethereumAddress: need(RE_ETH, ethereumAddress, 'ethereumAddress'),
      nodusAddress: need(RE_HEX128, nodusAddress, 'nodusAddress'),
      usdtAmount: needRaw(usdtAmountRaw, 'usdtAmount').toString(),
      nodusAmount: needRaw(nodusAmountRaw, 'nodusAmount').toString(),
      requestNumber: needU64(requestNumber, 'requestNumber'),
    },
  };
}

// ── the bot's answers, read for display only ────────────────────────────

// POST /amm/quote answer (amm_http.c route_quote). Not checked or verified (givens items 65, 69): the fields are
// only read so they can be shown and used; a shape that cannot be shown is reported as such.
export function readQuoteAnswer(json) {
  if (json && json.approved === false && typeof json.reason === 'string') return { approved: false, reason: json.reason };
  const q = json;
  if (q && q.approved === true && typeof q.direction === 'string' && typeof q.payTo === 'string' &&
      ['amount', 'number', 'estimatedFee', 'requestNumber', 'validUntil'].every(k => typeof q[k] === 'string' && DIGITS.test(q[k]))) {
    return {
      approved: true,
      quote: {
        direction: q.direction, amount: q.amount, number: q.number, estimatedFee: q.estimatedFee,
        requestNumber: q.requestNumber, validUntil: q.validUntil, payTo: q.payTo,
      },
    };
  }
  return { approved: false, reason: 'bad_answer' };
}

// POST /amm/liquidity/quote answer (amm_http.c route_add_quote).
export function readAddQuoteAnswer(json) {
  if (json && json.approved === false && typeof json.reason === 'string') return { approved: false, reason: json.reason };
  const q = json;
  if (q && q.approved === true && typeof q.payEthereum === 'string' && typeof q.payNodus === 'string' &&
      ['usdtAmount', 'nodusAmount', 'requestNumber', 'validUntil'].every(k => typeof q[k] === 'string' && DIGITS.test(q[k]))) {
    return {
      approved: true,
      quote: {
        usdtAmount: q.usdtAmount, nodusAmount: q.nodusAmount, requestNumber: q.requestNumber,
        validUntil: q.validUntil, payEthereum: q.payEthereum, payNodus: q.payNodus,
      },
    };
  }
  return { approved: false, reason: 'bad_answer' };
}

// ── plain words for the bot's refusal words (amm_http.h "REFUSAL WORDS") ─

const REFUSALS = {
  paused: 'Swaps are paused right now. Try again later.',
  stopped: 'The bot is not taking new swaps.',
  below_minimum: 'This amount is below the smallest swap the bot accepts.',
  above_maximum: 'This amount is above the largest single swap the bot accepts.',
  inflight_full: 'The bot is at its limit for money in flight. Try again in a few minutes.',
  no_liquidity: 'The pool cannot give anything for this amount.',
  cannot_pay: 'The bot cannot pay out this amount right now.',
  unavailable: 'The bot cannot read one of the chains it needs. Try again later.',
  busy: 'The bot is busy with other price requests. Try again later.',
  bad_request: 'The bot did not accept the request.',
  internal: 'The bot had an internal error. Try again later.',
  bad_answer: 'The bot\'s answer could not be read.',
  unreachable: 'The bot could not be reached. Nothing was signed or paid.',
  // answers to a signed request (the extension delivers it; the withdraw is posted by this site)
  bad_format: 'The bot rejected the signed request: its format is wrong.',
  bad_chain: 'The bot rejected the signed request: it names another chain.',
  bad_address: 'The bot rejected the request: the address does not match the signing key.',
  bad_signature: 'The bot rejected the request: the signature is not valid.',
  number_reused: 'This request number was already used. Get a new price.',
  unknown_number: 'The bot does not know this request number. Get a new price.',
  amount_mismatch: 'The amount does not match the price the bot gave. Get a new price.',
  number_used: 'This request number was already used for a payment.',
  open_approval: 'You already have an open swap for the same amount.',
  approval_expired: 'The price has expired. Get a new price.',
  no_position: 'There is no liquidity position for these two addresses.',
  not_found: 'The bot does not know that page.',
};

// `minNodusRaw`: the add minimum in force (from /amm/status); the fallback constant when not given.
export function refusalText(reason, context, minNodusRaw = LIQUIDITY_MIN_NODUS_RAW) {
  if (context === 'add' && reason === 'below_minimum') {
    return `A liquidity add needs at least ${nodusWithCommas(minNodusRaw)} NODUS, plus the matching USDT at the pool's current ratio.`;
  }
  return REFUSALS[reason] ?? `The bot refused: ${String(reason)}.`;
}

// The origin (scheme, host, port) of an address, no path, query or fragment. The page no longer uses it for the bot
// address (that is BOT_ORIGIN in bot.js, not the page's own origin); kept as a tested helper.
export const originOf = href => new URL(href).origin;

// The unit of what the bot gives (the output) for a swap direction: NODUS for USDT -> NODUS, USDT for NODUS -> USDT.
// A shown quote is rendered with the unit of its OWN direction, whatever the screen's direction is now.
export function outputUnit(direction) {
  return direction === 'usdt_to_nodus' ? { name: 'NODUS', decimals: NODUS_DECIMALS } : { name: 'USDT', decimals: USDT_DECIMALS };
}

// Shown when the bounded polling ends without a final state (plan section 7 step 8: never "failed").
export const STILL_PENDING_TEXT = 'Your swap is still in progress; the bot keeps working on it. Check again in a few minutes.';

// ── swap states (plan section 7 step 8, GET /amm/swap/<id>; amm_journal.h AMM_S_*) ─

const FINAL = {
  paid: { kind: 'done', text: 'The bot has sent your payout. The swap is complete.' },
  refunded: { kind: 'refunded', text: 'The amount you would receive was below your minimum, so the bot returned your payment.' },
  dropped: { kind: 'closed', text: 'Nothing was left to refund after the network fee, so nothing was sent back.' },
  expired: { kind: 'expired', text: 'No payment was seen within the approval time.' },
};
const PENDING = {
  approved: 'The bot has not seen a payment yet. If you paid, it shows here as soon as the bot sees it. If you did not pay, this request expires unpaid once the approval time has passed and the bot has checked that no payment came.',
  paid_waiting_depth: 'Payment seen. Waiting for network confirmations.',
  counted: 'Payment confirmed. The bot is processing the swap.',
  payout_pending: 'The bot is sending your payout.',
  refund_pending: 'The bot is sending your refund.',
  held: 'This payment is on hold for manual handling.',
  reversed: 'The bot is handling a reversal of this payment.',
  unknown: 'The bot is checking the state of this swap.',
};
// The short title of the status panel's third step, by the bot's state word; 'Payout' for anything else.
const STATE_TITLES = new Map([
  ['paid', 'Your payout has been sent'], ['refunded', 'Payment refunded'], ['dropped', 'Closed, nothing to refund'],
  ['expired', 'Request expired'], ['approved', 'Waiting for your payment'], ['paid_waiting_depth', 'Confirming your payment'],
  ['counted', 'Payment confirmed'], ['payout_pending', 'Sending your payout'], ['refund_pending', 'Sending your refund'],
  ['held', 'On hold'], ['reversed', 'Payment being reversed'], ['unknown', 'Checking'],
]);

// payout_pending, by the direction the answer names. NODUS -> USDT: the payout is USDT on Ethereum; the amount is the
// answer's `paid` when it is a string of digits (USDT raw units). The answer says nothing about the transaction, so the
// text does not claim it is mined. USDT -> NODUS: the payout is NODUS; no wait number (see PAYOUT_FINAL_DEPTH_ETH).
function payoutPendingText(answer) {
  if (answer?.direction === 'nodus_to_usdt') {
    const amount = typeof answer.paid === 'string' && /^[0-9]+$/.test(answer.paid)
      ? ` of ${displayAmount(BigInt(answer.paid), USDT_DECIMALS)} USDT` : '';
    return `Your payout${amount} is on its way. The bot marks the swap complete after ${PAYOUT_FINAL_DEPTH_ETH} Ethereum blocks ` +
      `(about ${PAYOUT_FINAL_SECONDS_ETH} seconds); the USDT can reach your wallet before that.`;
  }
  if (answer?.direction === 'usdt_to_nodus') {
    return 'Your NODUS payout is on its way. The bot marks the swap complete once that payment is confirmed in a Nodus block.';
  }
  return PENDING.payout_pending;
}

// Display only: the third step's title for a state word, never read back as a state (describeSwapState stays the state).
export const stateLabel = state => (typeof state === 'string' && STATE_TITLES.get(state)) || 'Payout';

// Final = the bot has decided and finished. Everything else is "pending": never "failed" for a non-final
// state (plan section 7 step 8).
export function describeSwapState(answer) {
  const state = typeof answer?.state === 'string' ? answer.state : '';
  if (FINAL[state]) return { final: true, kind: FINAL[state].kind, state, text: FINAL[state].text };
  let text = PENDING[state] ?? 'In progress.';
  if (state === 'payout_pending') text = payoutPendingText(answer);
  if (state === 'paid_waiting_depth' && answer.waitingForRoom === true) {
    text = 'Payment seen. It is waiting in line until the bot has room under its limit for money in flight.';
  }
  return { final: false, kind: 'pending', state, text };
}
