// NODUS balance / send / confirmation on the wallet side — package (d) of
// docs/plans/2026-09-25-web-wallet-nodus-send-design.md (§0a.3, §1.4). Every
// chain operation goes through the send module's client (src/nodus/client.js);
// this file only validates what crosses that boundary and applies the wallet's
// rules. Nothing here is reachable until a module reports 'ready'
// (src/nodus/send-module.js holds null until package (c3) lands).
//
// Rules applied here (sources):
// - expiry_height = tip + 90; tip 0 or unknown -> do not send
//   (docs/plans/2026-09-26-note-to-web-wallet-session-expiry.md items 1-2;
//   nodus/tools/nodus-cli.c:93-94 CLI_ENV_EXPIRY_AHEAD = 100 - 10).
// - Pending-send coins stay locked; a resend before expiry reuses the same
//   coins; different coins only once the chain passed expiry_height AND the
//   first send was seen not to enter (same note, item 3; design §1.4, G7).
// - Confirmation screen values are decoded from the signed envelope (G1).
// - Amounts are decimal strings at the module boundary, BigInt here (RT1 L4 F10).
import { amountUnits, formatUnits } from '../core.js';
import { NODUS_ASSET } from '../nodus/network.js';

const HEX128 = /^[0-9a-f]{128}$/, HEX64 = /^[0-9a-f]{64}$/, RAW = /^(0|[1-9]\d{0,19})$/;
const U64_MAX = 2n ** 64n - 1n;
// nodus/tools/nodus-cli.c:93-94: NODUS_CMT_APP_MAX_EXPIRY_AHEAD (100) - 10.
export const NODUS_EXPIRY_AHEAD = 90n;
// nodus/tools/nodus-cli.c:2778 T6_SPEND_MAX_IN.
export const NODUS_MAX_INPUTS = 15;
// Upper bound on coins accepted from one list() answer. Not a chain rule: a
// sanity cap so a hostile node cannot make the wallet hold an unbounded array.
const MAX_LISTED_COINS = 1000;
const DECIMALS = NODUS_ASSET.decimals;

// A raw-unit decimal integer string from the module -> BigInt within uint64.
export function rawUnits(value, what) {
  if (typeof value !== 'string' || !RAW.test(value)) throw new Error(`The Nodus module returned an invalid ${what}.`);
  const units = BigInt(value);
  if (units > U64_MAX) throw new Error(`The Nodus module returned an invalid ${what}.`);
  return units;
}
// A Nodus address is the 128-hex SHA3-512 fingerprint; it has no checksum, so
// the review shows it in full. Case is normalized to the lowercase form the
// wallet itself displays (src/nodus/derive.js bytesToHex).
export function nodusRecipient(value) {
  const to = typeof value === 'string' ? value.trim().toLowerCase() : '';
  if (!HEX128.test(to)) throw new Error('Enter a Nodus address: 128 characters, 0-9 and a-f.');
  return to;
}
export function nodusAmountUnits(value) {
  const units = amountUnits(typeof value === 'string' ? value.trim() : value, DECIMALS);
  if (units > U64_MAX) throw new Error('Amount is out of range.');
  return units;
}
// tip: the chain height the node reported. 0 is what the node answers on a
// read error (session-expiry note item 2), so 0 and "unknown" both refuse.
export function expiryHeightFor(tip) {
  if (typeof tip !== 'bigint' || tip <= 0n) throw new Error('The current Nodus block height is unknown. Nothing was sent; try again later.');
  return tip + NODUS_EXPIRY_AHEAD;
}
function parseTip(value) {
  if (value === undefined || value === null) return expiryHeightFor(undefined);
  return rawUnits(value, 'block height');
}
function isNodusRow(row) { return row?.chain === NODUS_ASSET.chain; }
// A genesis-claim Activity record (0.1.26): `hash` is the coin the claim
// creates (its output id — the same for every signature variant) and
// `inputs` is [that same id]. That pair is the marker: after a reload
// src/activity-storage.js keeps only hash / expiryHeight / fromHeight /
// inputs of a NODUS row, and a send never lists its own intent id as one of
// its inputs.
export function isClaimRow(row) {
  return isNodusRow(row) && Array.isArray(row.inputs) && row.inputs.length === 1 && row.inputs[0] === row.hash;
}
// Coins of every NODUS send that is not known to have stayed out of the chain.
// Only a scan result sets 'expired' (tip past expiry_height and the intent not
// found); 'confirmed' coins are spent; every other state keeps them locked.
// A claim record holds no coin of this wallet (its "input" is the coin it
// creates), so it locks nothing.
export function lockedInputs(rows) {
  const locked = new Set();
  for (const row of rows) if (isNodusRow(row) && !isClaimRow(row) && row.status !== 'expired') for (const input of row.inputs || []) locked.add(input);
  return locked;
}
// Which coins a resend of `row` may use (session-expiry note item 3):
// - 'confirmed': none, it is already in the chain;
// - 'expired': any unlocked coins (returns null = no restriction);
// - anything else: exactly the same coins, so the two envelopes conflict and
//   at most one of them can ever be applied.
export function resendInputs(row) {
  if (!isNodusRow(row) || isClaimRow(row)) throw new Error('Not a Nodus send.');
  if (row.status === 'confirmed') throw new Error('This transfer is already in the chain. Do not send it again.');
  if (row.status === 'expired') return null;
  return [...row.inputs];
}
function parseCoins(listing) {
  if (!listing || !Array.isArray(listing.coins) || listing.coins.length > MAX_LISTED_COINS) throw new Error('The Nodus module returned an invalid coin list.');
  const seen = new Set();
  return listing.coins.map(coin => {
    if (!coin || typeof coin.nullifier !== 'string' || !HEX128.test(coin.nullifier) || seen.has(coin.nullifier)) throw new Error('The Nodus module returned an invalid coin list.');
    seen.add(coin.nullifier);
    const amount = rawUnits(coin.amount, 'coin amount');
    if (amount === 0n) throw new Error('The Nodus module returned an invalid coin list.');
    return { nullifier: coin.nullifier, amount: coin.amount };
  });
}
function parseBalance(result) {
  if (!result) throw new Error('The Nodus module returned an invalid balance.');
  const total = rawUnits(result.total, 'balance'), spendable = rawUnits(result.spendable, 'balance');
  if (spendable > total) throw new Error('The Nodus module returned an invalid balance.');
  return { total, spendable };
}
// Everything shown on the review screen comes from here: the module's own
// decoding of the envelope it signed. Anything malformed stops the send.
export function decodeBuilt(built) {
  const d = built?.decoded;
  if (!built || !(built.envelope instanceof Uint8Array) || built.envelope.length === 0 || typeof built.intentId !== 'string' || !HEX128.test(built.intentId) || !d) throw new Error('The Nodus module returned an invalid transaction.');
  if (typeof d.recipient !== 'string' || !HEX128.test(d.recipient) || typeof d.chainId !== 'string' || !HEX64.test(d.chainId)) throw new Error('The Nodus module returned an invalid transaction.');
  if (!Array.isArray(d.inputs) || d.inputs.length < 1 || d.inputs.length > NODUS_MAX_INPUTS || new Set(d.inputs).size !== d.inputs.length || !d.inputs.every(input => typeof input === 'string' && HEX128.test(input))) throw new Error('The Nodus module returned an invalid transaction.');
  return {
    envelope: built.envelope, intentId: built.intentId, recipient: d.recipient, chainId: d.chainId, inputs: [...d.inputs],
    amount: rawUnits(d.amount, 'transaction amount'), fee: rawUnits(d.fee, 'network fee'), change: rawUnits(d.change, 'change amount'),
    expiryHeight: rawUnits(d.expiryHeight, 'expiry height')
  };
}
const nodusText = units => `${formatUnits(units, DECIMALS)} ${NODUS_ASSET.symbol}`;

// Portfolio balance read (src/portfolio-view.js readBalances): the spendable
// native balance. Any failure throws, which the portfolio shows as "Balance
// unavailable" — never as zero (design G5).
export async function balances(chain, address, _endpoint, { signal, client } = {}) {
  if (chain !== NODUS_ASSET.chain || !client || client.state !== 'ready') throw new Error('Nodus connection is not ready.');
  if (address !== client.fingerprint) throw new Error('Nodus address does not match the connected identity.');
  const { spendable } = parseBalance(await client.balance({ signal }));
  return [{ symbol: NODUS_ASSET.symbol, balance: formatUnits(spendable, DECIMALS) }];
}

// Builds and signs one SPEND for review. `locked`: coins of pending sends
// (lockedInputs). `inputs`: a resend's exact coins (resendInputs), else null.
export async function prepare({ client, from, to, amount, locked = new Set(), inputs = null }) {
  if (!client || client.state !== 'ready') throw new Error('Nodus sending is not available right now.');
  if (from !== client.fingerprint) throw new Error('Nodus address does not match the connected identity.');
  const recipient = nodusRecipient(to), units = nodusAmountUnits(amount);
  const { spendable } = parseBalance(await client.balance());
  const listing = await client.list();
  const coins = parseCoins(listing);
  // A read error on the node answers "0 coins" (design §1.4); with a positive
  // spendable balance, an empty list is a read failure, not "insufficient".
  if (coins.length === 0 && spendable > 0n) throw new Error('Your coin list could not be read. Nothing was sent; try again later.');
  const tip = parseTip(listing.tip), expiryHeight = expiryHeightFor(tip);
  let candidates;
  if (inputs) {
    const listed = new Map(coins.map(coin => [coin.nullifier, coin]));
    if (!inputs.every(input => listed.has(input))) throw new Error('The coins of the earlier send are no longer listed. Check its status before sending again.');
    candidates = inputs.map(input => listed.get(input));
  } else {
    candidates = coins.filter(coin => !locked.has(coin.nullifier));
    if (candidates.length === 0) throw new Error(locked.size ? 'Your coins are held by a pending send. Wait for it to be included or to expire.' : 'Insufficient NODUS balance.');
  }
  const decoded = decodeBuilt(await client.buildAndSign({ to: recipient, amount: units.toString(), expiryHeight: expiryHeight.toString(), coins: candidates }));
  // The signed envelope must be exactly what was requested, or nothing is shown.
  if (decoded.recipient !== recipient || decoded.amount !== units || decoded.expiryHeight !== expiryHeight || decoded.chainId !== client.chainId) throw new Error('The signed transaction does not match your request. Nothing was sent.');
  const allowed = new Set(candidates.map(coin => coin.nullifier));
  if (!decoded.inputs.every(input => allowed.has(input))) throw new Error('The signed transaction uses coins it may not use. Nothing was sent.');
  const review = [
    ['Network', 'Nodus'],
    ['From', from],
    ['To', decoded.recipient],
    ['Address check', 'Nodus addresses have no checksum. Compare all 128 characters with your source.'],
    ['Amount', nodusText(decoded.amount)],
    ['Network fee', nodusText(decoded.fee)],
    ['Change back to you', nodusText(decoded.change)],
    ['Valid until block', decoded.expiryHeight.toString()],
    ['Chain ID', decoded.chainId],
    ['Fee note', 'The network fee may be charged even if the transfer fails.']
  ];
  if (listing.truncated === true) review.push(['Coin list', 'Your coin list may be incomplete; the transfer uses only the coins listed.']);
  let used = false;
  return {
    to: decoded.recipient, amount: formatUnits(decoded.amount, DECIMALS), symbol: NODUS_ASSET.symbol, fee: nodusText(decoded.fee),
    // Review-dialog timeout only (UI). The envelope's own validity is its
    // expiry height, checked by the chain.
    expiresAt: Date.now() + 60000,
    intentId: decoded.intentId, expiryHeight: decoded.expiryHeight.toString(), review,
    // onBroadcast must make the pending-send record durable BEFORE the envelope
    // leaves the browser (the same rule as the other networks, src/app.js).
    async send(onBroadcast) {
      if (used) throw new Error('This review is already closed.');
      used = true;
      await onBroadcast({ hash: decoded.intentId, expiryHeight: decoded.expiryHeight.toString(), fromHeight: (tip + 1n).toString(), inputs: [...decoded.inputs] });
      const result = await client.submit({ envelope: decoded.envelope });
      if (!result || result.accepted !== true) throw new Error('The Nodus network did not accept this transfer. Its coins stay held until the transfer expires.');
      return decoded.intentId;
    }
  };
}

// Activity tracker check for a pending NODUS send (src/activity.js
// watchActivity `check`): scans blocks fromHeight..expiryHeight for its
// intent_id. The answer comes from ONE node (design §3 A3, §5 item 16).
//
// A claim record (isClaimRow) is scanned the same way: the module also
// matches an applied claim that created the coin `row.hash`. A claim has no
// expiry block — the record's expiryHeight only bounds this scan — so past
// it the answer comes from claimStatus(): claimed (proven) -> confirmed,
// otherwise 'expired' with a note that says what that means for a claim.
export async function checkNodusActivity(row, { signal, client } = {}) {
  if (!isNodusRow(row) || !HEX128.test(row.hash)) throw new Error('Invalid activity record.');
  if (!client || client.state !== 'ready') throw new Error('Nodus connection is not ready.');
  const claim = isClaimRow(row);
  const fromHeight = rawUnits(row.fromHeight, 'block height'), expiryHeight = rawUnits(row.expiryHeight, 'block height');
  const result = await client.scanConfirm({ intentId: row.hash, fromHeight: row.fromHeight, toHeight: row.expiryHeight }, { signal });
  if (!result || typeof result.found !== 'boolean') throw new Error('The Nodus module returned an invalid status.');
  const tip = rawUnits(result.tip, 'block height');
  if (result.found) {
    const height = rawUnits(result.height, 'block height');
    if (height < fromHeight || height > expiryHeight) throw new Error('The Nodus module returned an invalid status.');
    return { status: 'confirmed', note: claim ? `Allocation claimed in block ${height} (reported by one Nodus node).` : `Included in block ${height} (reported by one Nodus node).` };
  }
  if (claim) {
    if (tip <= expiryHeight) return { status: 'pending', note: `Waiting for the claim to be included (checking up to block ${expiryHeight}).` };
    const status = parseClaimStatus(await client.claimStatus({ signal }));
    if (status.found && status.claimed === 'yes') return { status: 'confirmed', note: 'Your allocation has been claimed (reported by one Nodus node).' };
    return { status: 'expired', note: `Not seen in blocks ${fromHeight} to ${expiryHeight}. If your allocation is still offered for claiming, you can claim it again; an allocation is never paid out twice.` };
  }
  if (tip > expiryHeight) return { status: 'expired', note: `Not included before block ${expiryHeight}; it can no longer be included and its coins are free again.` };
  return { status: 'pending', note: `Waiting for inclusion; valid until block ${expiryHeight}.` };
}

// ── Genesis claim (0.1.26) ────────────────────────────────────────────────
// The module side is nodus-cli `v2-claim` (crypto/nodus-send-wasm.c "GENESIS
// CLAIM"); this side validates what crosses the boundary and applies the
// same fail-closed rules as prepare().
const CLAIM_WINDOWS = ['open', 'not-open', 'closed'], CLAIM_STATES = ['yes', 'no-evidence', 'unknown'];
export function parseClaimStatus(result) {
  const invalid = () => new Error('The Nodus module returned an invalid claim status.');
  if (!result || typeof result.found !== 'boolean') throw invalid();
  if (!result.found) return { found: false };
  const amount = rawUnits(result.amount, 'claim amount'), tip = rawUnits(result.tip, 'block height');
  const startHeight = rawUnits(result.startHeight, 'block height'), endHeight = rawUnits(result.endHeight, 'block height');
  if (amount === 0n || tip === 0n || startHeight > endHeight || !CLAIM_WINDOWS.includes(result.window) || !CLAIM_STATES.includes(result.claimed) || typeof result.outputId !== 'string' || !HEX128.test(result.outputId)) throw invalid();
  return { found: true, amount, tip, startHeight, endHeight, window: result.window, claimed: result.claimed, outputId: result.outputId };
}
function claimReady(client, from) {
  if (!client || client.state !== 'ready') throw new Error('Nodus is not connected right now.');
  if (from !== client.fingerprint) throw new Error('Nodus address does not match the connected identity.');
}
// Whether the open wallet has an allocation it can claim now. Resolves the
// parsed status plus `claimable` (found, window open, not proven claimed).
export async function claimStatus({ client, from, signal } = {}) {
  claimReady(client, from);
  const status = parseClaimStatus(await client.claimStatus({ signal }));
  return { ...status, claimable: status.found && status.window === 'open' && status.claimed !== 'yes', amountText: status.found ? nodusText(status.amount) : undefined };
}
// Builds and signs the claim for review, in the shape src/app.js's review
// dialog and recordActivity() consume (the wallet.js reviewed() contract:
// cancel(), confirm(onBroadcast) usable once, refused after expiresAt).
export async function prepareClaim({ client, from } = {}) {
  claimReady(client, from);
  const status = parseClaimStatus(await client.claimStatus());
  if (!status.found) throw new Error('This wallet has no allocation to claim.');
  if (status.claimed === 'yes') throw new Error('Your allocation has already been claimed.');
  if (status.window === 'not-open') throw new Error(`Claiming opens at block ${status.startHeight}.`);
  if (status.window === 'closed') throw new Error(`The claim period ended at block ${status.endHeight}.`);
  const built = await client.claimBuild(), d = built?.decoded;
  if (!built || !(built.bytes instanceof Uint8Array) || built.bytes.length === 0 || typeof built.claimId !== 'string' || !HEX128.test(built.claimId) || !d) throw new Error('The Nodus module returned an invalid claim.');
  if (typeof d.recipient !== 'string' || !HEX128.test(d.recipient) || typeof d.chainId !== 'string' || !HEX64.test(d.chainId) || typeof d.nullifier !== 'string' || !HEX128.test(d.nullifier) || typeof d.outputId !== 'string' || !HEX128.test(d.outputId)) throw new Error('The Nodus module returned an invalid claim.');
  const amount = rawUnits(d.amount, 'claim amount');
  rawUnits(d.leafIndex, 'allocation index');
  // The signed claim must pay exactly this wallet's allocation to this
  // wallet, on the connected chain, or nothing is shown.
  if (d.recipient !== from || amount !== status.amount || d.chainId !== client.chainId || d.outputId !== status.outputId) throw new Error('The signed claim does not match your allocation. Nothing was sent.');
  const fromHeight = status.tip + 1n, scanTo = status.tip + NODUS_EXPIRY_AHEAD;
  const review = [
    ['Network', 'Nodus testnet'],
    ['Action', 'Claim your allocation'],
    ['Amount', nodusText(amount)],
    ['Paid to', `${d.recipient} (your own address)`],
    ['Network fee', 'None'],
    ['Chain ID', d.chainId],
    ['Note', 'An allocation can be claimed only once. After it is included, the amount becomes part of your NODUS balance.']
  ];
  let used = false;
  const expiresAt = Date.now() + 60000;
  return {
    kind: 'claim', chain: NODUS_ASSET.chain, from, to: d.recipient, symbol: NODUS_ASSET.symbol, amount: formatUnits(amount, DECIMALS),
    endpoint: undefined, fee: 'None', expiresAt, review, intentId: d.outputId,
    cancel() { used = true; },
    async confirm(onBroadcast) {
      if (used) throw new Error('This review is already closed.');
      used = true; // an ambiguous submission is never retried automatically
      if (Date.now() >= expiresAt) throw new Error('Review expired. Prepare the claim again.');
      // The record is durable before the claim leaves the browser (same rule
      // as a send). inputs = [hash] marks it as a claim (isClaimRow).
      await onBroadcast({ hash: d.outputId, expiryHeight: scanTo.toString(), fromHeight: fromHeight.toString(), inputs: [d.outputId] });
      const result = await client.claimSubmit({ bytes: built.bytes });
      if (!result || result.accepted !== true) throw new Error(`The Nodus network did not accept this claim.${typeof result?.message === 'string' && result.message ? ` ${result.message}` : ''}`);
      return d.outputId;
    }
  };
}
