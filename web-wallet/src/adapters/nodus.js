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
// - HF-4 (docs/plans/2026-10-02-onchain-names-design.md rev 4 §1.6;
//   decision 2026-10-02-onchain-names.md): before anything is built the
//   node is asked which rule-set generation it runs (client.rulesetInfo —
//   the module picks the pinned generation whose tuple equals the answer
//   and refuses an older node or an unknown generation); a generation-1
//   envelope never expires past H-1 once a switch at H is committed, and
//   with no valid expiry left nothing is built (expiryHeightFor — the rule
//   of nodus-cli cli_env_expiry and nodus-send-wasm.c nsw_expiry_for).
// - A recipient may be a chain name (src/nodus/names.js): resolved by ONE
//   node (decision item 9, accepted risk) and shown on the review next to
//   the address it resolved to; a name that does not resolve is an error.
// - Pending-send coins stay locked; a resend before expiry reuses the same
//   coins; different coins only once the chain passed expiry_height AND the
//   first send was seen not to enter (same note, item 3; design §1.4, G7).
// - Confirmation screen values are decoded from the signed envelope (G1).
// - Amounts are decimal strings at the module boundary, BigInt here (RT1 L4 F10).
import { amountUnits, formatUnits } from '../core.js';
import { NODUS_ASSET, NODUS_TOKEN_ID, nodusTokens } from '../nodus/network.js';
import { chainName, chainNameOk, parseNameOf } from '../nodus/names.js';
import { isNodusBusy } from '../nodus/client.js';

const HEX128 = /^[0-9a-f]{128}$/, HEX64 = /^[0-9a-f]{64}$/, RAW = /^(0|[1-9]\d{0,19})$/;
const ZERO128 = '0'.repeat(128);
const U64_MAX = 2n ** 64n - 1n;
// nodus/tools/nodus-cli.c:93-94: NODUS_CMT_APP_MAX_EXPIRY_AHEAD (100) - 10.
export const NODUS_EXPIRY_AHEAD = 90n;
// nodus/tools/nodus-cli.c:2778 T6_SPEND_MAX_IN.
export const NODUS_MAX_INPUTS = 15;
// Upper bound on coins accepted from one list() answer. Not a chain rule: a
// sanity cap so a hostile node cannot make the wallet hold an unbounded array.
const MAX_LISTED_COINS = 1000;
const DECIMALS = NODUS_ASSET.decimals;
// The signed envelope's full-wire id (0.1.78): the module's nsw_built_wire,
// the builder's copy of the preflight wire_id (nodus/src/client/
// nodus_v2_spend.c, nodus_v2_stake.c, nodus_v2_name.c: `memcpy(out->wire_id,
// pf->wire_id, 64)`) — the id the node's address history stores as "wire"
// (nodus/src/witness/nodus_witness_addr_index.h). It differs from the intent
// id the Activity record is keyed by (the hedged signature is inside it), so
// it is kept only in this tab's record (src/activity.js recordActivity) to
// show a send once when the node's history lists it (src/nodus/history.js).
// A module without it (older build, test mock): absent — never invented.
const builtWire = built => (typeof built?.wireId === 'string' && HEX128.test(built.wireId) ? { wire: built.wireId } : {});
// Submits one signed envelope (dnac_spend). A node that answered "busy"
// (web 0.1.119, isNodusBusy) forwarded nothing, so its error carries the
// SAME signed bytes and their intent id (web 0.1.124): the wallet keeps them
// with the pending record and sends exactly them again on "Try again"
// (src/nodus/resubmit.js). A new signing would give different bytes (hedged
// signature) and could not use the coins the record holds. `refused(result)`
// is the text of a refusal; any other failure is thrown as it came.
async function submitSigned(client, envelope, intentId, refused) {
  let result;
  try { result = await client.submit({ envelope }); }
  catch (error) {
    if (isNodusBusy(error)) Object.assign(error, { envelope, intentId });
    throw error;
  }
  if (!result || result.accepted !== true) throw new Error(refused(result));
}
const refusalDetail = result => (typeof result?.message === 'string' && result.message ? ` ${result.message}` : '');

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
// The module's rulesetInfo() answer (src/nodus/send-module.js), checked:
// { generation >= 1, tip, gen2Height (0 = no switch committed) } as BigInt.
export function parseRulesetInfo(result) {
  if (!result) throw new Error('The Nodus module returned invalid network rules.');
  const generation = rawUnits(result.generation, 'rule-set generation');
  if (generation === 0n) throw new Error('The Nodus module returned invalid network rules.');
  return { generation, tip: rawUnits(result.tip, 'block height'), gen2Height: rawUnits(result.gen2Height, 'block height') };
}
// The module's rulesetCompat() answer (src/nodus/send-module.js), checked:
// outcome 0 / 1 / 2 as the module decided it (nodus_ruleset_compat — the
// rule is NOT repeated here), the generations as BigInt, the heights as
// BigInt. Outcome 1 always names a switch above the tip. Throws on any
// other shape. For the update notice only (src/nodus/update-notice.js).
export function parseRulesetCompat(result) {
  const bad = () => new Error('The Nodus module returned an invalid update check.');
  if (!result || ![0, 1, 2].includes(result.outcome)) throw bad();
  const out = {
    outcome: result.outcome,
    generation: rawUnits(result.generation, 'rule-set generation'),
    nextGeneration: rawUnits(result.nextGeneration, 'rule-set generation'),
    nextHeight: rawUnits(result.nextHeight, 'block height'),
    tip: rawUnits(result.tip, 'block height'),
    maxGeneration: rawUnits(result.maxGeneration, 'rule-set generation')
  };
  if (out.outcome === 1 && (out.nextGeneration === 0n || out.nextHeight <= out.tip)) throw bad();
  return out;
}
// tip: the chain height the coin listing reported. 0 is what the node
// answers on a read error (session-expiry note item 2), so 0 and "unknown"
// both refuse. ruleset: parseRulesetInfo's result (required). The rule of
// nodus-cli cli_env_expiry: tip + 90, and for a generation-1 envelope while
// a switch at H is committed never past H - 1, judged against the larger
// of the two tips; with H - 1 not above it no expiry is valid.
export function expiryHeightFor(tip, ruleset) {
  if (typeof tip !== 'bigint' || tip <= 0n) throw new Error('The current Nodus block height is unknown. Nothing was sent; try again later.');
  if (!ruleset || typeof ruleset.generation !== 'bigint' || typeof ruleset.gen2Height !== 'bigint' || typeof ruleset.tip !== 'bigint') throw new Error('The Nodus network rules are unknown. Nothing was sent; try again later.');
  let expiry = tip + NODUS_EXPIRY_AHEAD;
  if (expiry > U64_MAX) throw new Error('The current Nodus block height is out of range.');
  const hi = tip > ruleset.tip ? tip : ruleset.tip, H = ruleset.gen2Height;
  if (ruleset.generation === 1n && H !== 0n) {
    if (H - 1n <= hi) throw new Error(`The Nodus network switches to new transaction rules at block ${H}, and a transaction made now could not be included before it. Nothing was sent; try again after block ${H}.`);
    if (expiry > H - 1n) expiry = H - 1n;
  }
  return expiry;
}
// The review window (prepare()'s expiresAt) and the shortest gap between
// two blocks: a node waits timeout_commit = 4000 ms after a commit before
// the next height starts (nodus/src/witness/nodus_witness_cmt_node.c:1773),
// so at most NODUS_REVIEW_MS / NODUS_MIN_BLOCK_MS blocks pass while the
// review is open.
export const NODUS_REVIEW_MS = 60000;
export const NODUS_MIN_BLOCK_MS = 4000;
// Review rows for an expiry capped by a rule-set switch (none otherwise).
export function expiryCapRows(tip, expiryHeight, ruleset) {
  if (expiryHeight >= tip + NODUS_EXPIRY_AHEAD) return [];
  const rows = [['Rule change', `The Nodus network switches to new transaction rules at block ${ruleset.gen2Height}. This transaction is built for the current rules and can only be included up to block ${expiryHeight}.`]];
  const left = expiryHeight - tip;
  if (left * BigInt(NODUS_MIN_BLOCK_MS) <= BigInt(NODUS_REVIEW_MS)) rows.push(['Timing', `Only ${left} ${left === 1n ? 'block remains' : 'blocks remain'} before it expires — fewer than can pass while this review is open. If you confirm too late it is not included: nothing is spent, and its coins are free again after block ${expiryHeight}.`]);
  return rows;
}

// ── Chain names (HF-4) ───────────────────────────────────────────────────
// The module's nameLookup() answer, checked.
export function parseNameLookup(result) {
  const invalid = () => new Error('The Nodus module returned an invalid name lookup.');
  if (!result || typeof result.found !== 'boolean') throw invalid();
  const committedHeight = rawUnits(result.committedHeight, 'block height');
  if (!result.found) return { found: false, committedHeight };
  if (typeof result.owner !== 'string' || !HEX128.test(result.owner)) throw invalid();
  const registeredHeight = rawUnits(result.registeredHeight, 'block height');
  if (registeredHeight === 0n) throw invalid();
  return { found: true, owner: result.owner, registeredHeight, committedHeight };
}
// `name` (lower-case, src/nodus/names.js) -> its owner's fingerprint, from
// ONE node's committed state. A name nobody holds is an error, never a
// fallback to anything else.
export async function resolveChainName(client, name) {
  if (!client || client.state !== 'ready' || !client.nameable) throw new Error('Sending to a chain name needs the Nodus network connection, which is not available right now.');
  if (!chainNameOk(name)) throw new Error('Not a chain name: 3 to 36 letters a-z and digits.');
  const found = parseNameLookup(await client.nameLookup({ name }));
  if (!found.found) throw new Error(`No one has registered the chain name "${name}". Nothing was sent.`);
  return found;
}
// The profile wallet field of each network a name can be sent to on
// (messenger/dht/client/dna_profile.h dna_wallets_t). No field is used for
// another network.
export const PROFILE_ADDRESS_FIELD = Object.freeze({ ethereum: 'eth', bsc: 'bsc', solana: 'sol', tron: 'trx' });
// A non-NODUS send to a chain name: the owner (resolveChainName), then the
// address the owner published for `chain` in its profile, read and
// signature-checked by the module. The caller's adapter still checks the
// address format before anything is built.
export async function resolveNameAddress({ client, chain, name }) {
  const field = PROFILE_ADDRESS_FIELD[chain];
  if (!field) throw new Error('Chain names cannot be used on this network.');
  const found = await resolveChainName(client, name);
  const result = await client.profileAddress({ owner: found.owner, field });
  if (!result || typeof result.address !== 'string' || !result.address || result.address.length > 128 || result.address.trim() !== result.address) throw new Error('The Nodus module returned an invalid profile address.');
  return { name, owner: found.owner, address: result.address, committedHeight: found.committedHeight };
}
// The review rows that say where an address came from: the name, its
// source and (showOwner) the Nodus ID that owns it. `via`: how the address
// was read after the owner was found (non-NODUS sends).
export function nameReviewRows({ name, owner, committedHeight }, { via = '', showOwner = true } = {}) {
  const rows = [
    ['To (chain name)', name],
    ['Recipient source', `Chain name${via ? `, then ${via}` : ''} — looked up on one Nodus node (state of block ${committedHeight}).`]
  ];
  if (showOwner) rows.push(['Name owner (Nodus ID)', owner]);
  return rows;
}
// In place of the "Address check" row when the address came from a name.
export const NAME_CHECK_ROW = Object.freeze(['Name check', 'Names can look alike (for example the digit 0 and the letter o). Check that the name is exactly the one the recipient gave you.']);
// A NODUS recipient as typed: a 128-hex address, or a chain name resolved
// to its owner. -> { recipient, resolved? } (resolved = resolveChainName's
// result plus the name).
export async function resolveNodusRecipient(client, value) {
  const typed = typeof value === 'string' ? value.trim() : '';
  if (HEX128.test(typed.toLowerCase())) return { recipient: nodusRecipient(typed) };
  const name = chainName(typed);
  if (!name) throw new Error('Enter a Nodus address (128 characters, 0-9 and a-f) or a chain name (3 to 36 letters a-z and digits).');
  const found = await resolveChainName(client, name);
  return { recipient: found.owner, resolved: { ...found, name } };
}
export function parseTip(value) {
  if (value === undefined || value === null) return expiryHeightFor(undefined);
  return rawUnits(value, 'block height');
}
function isNodusRow(row) { return row?.chain === NODUS_ASSET.chain; }
// A genesis-claim Activity record (0.1.26): `hash` is the coin the claim
// creates (its output id — the same for every signature variant) and
// `inputs` is [that same id]. That pair is the marker: a send never lists its
// own intent id as one of its inputs. The marker alone is NOT enough to hold
// a row out of the coin lock (BUGS W-25: a token row, or any row, shaped
// inputs:[X] hash:X would free its inputs): a real claim of this wallet is
// also what prepareClaim records — the NODUS asset (src/activity.js
// recordActivity: symbol NODUS, no tokenId; a token send always carries its
// tokenId) paying this wallet's OWN address (`to` = `address`, checked above
// by prepareClaim: recipient === from). Every one of those fields survives a
// reload (src/activity-storage.js readActivityRow), so the check is the same
// before and after it.
export function isClaimRow(row) {
  return isNodusRow(row) && Array.isArray(row.inputs) && row.inputs.length === 1 && row.inputs[0] === row.hash
    && row.tokenId === undefined && row.symbol === NODUS_ASSET.symbol && typeof row.address === 'string' && row.to === row.address;
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
// The wallet's strict view of its own NODUS coins, for releasing the lock of a
// quarantined Activity record (src/app.js reconcileQuarantine): the balance
// and the coin list, checked like prepare() checks them before a send — an
// invalid list, a tip of 0 (the node's answer to a failed read), or an empty
// list under a positive balance is an error, never "no coins".
// -> { coins: Set of nullifiers, tip: BigInt }
export async function coinView({ client, from } = {}) {
  if (!client || client.state !== 'ready') throw new Error('Nodus connection is not ready.');
  if (from !== client.fingerprint) throw new Error('Nodus address does not match the connected identity.');
  const { spendable } = parseBalance(await client.balance());
  const listing = await client.list();
  const coins = parseCoins(listing), tip = parseTip(listing.tip);
  if (tip <= 0n || (coins.length === 0 && spendable > 0n)) throw new Error('Your coin list could not be read.');
  return { coins: new Set(coins.map(coin => coin.nullifier)), tip };
}
// Whether the lock of a quarantined record (src/activity-storage.js
// parseActivity `quarantined`: { inputs, expiryHeight?, tokenRow }) can be
// released, given a strict view (coinView). Two reasons only:
// - an input of it is no longer one of the wallet's coins: the transaction
//   spends every input or none, so one spent coin means it can never be
//   applied (a double spend) and holding the rest buys nothing. Only for a
//   native record: a token record's token coins are not in this native list.
//   Released when NONE of its inputs is listed any more (every one spent).
// - its expiry is known and the chain is past it: it can no longer be applied.
// Otherwise (an input still unspent and no usable expiry) it stays held.
export function quarantineReleasable(entry, view) {
  if (!entry || !view || !(view.coins instanceof Set) || typeof view.tip !== 'bigint' || view.tip <= 0n) return false;
  if (typeof entry.expiryHeight === 'string' && /^[1-9]\d{0,19}$/.test(entry.expiryHeight) && view.tip > BigInt(entry.expiryHeight)) return true;
  return entry.tokenRow !== true && Array.isArray(entry.inputs) && entry.inputs.length > 0 && entry.inputs.every(input => !view.coins.has(input));
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
export function parseCoins(listing) {
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
export function parseBalance(result) {
  if (!result) throw new Error('The Nodus module returned an invalid balance.');
  const total = rawUnits(result.total, 'balance'), spendable = rawUnits(result.spendable, 'balance');
  if (spendable > total) throw new Error('The Nodus module returned an invalid balance.');
  return { total, spendable };
}
// ── Pinned tokens (design docs/plans/2026-10-22-connect-native-tokens-design.md
// §6; operator "Yalnız tUSDT") ────────────────────────────────────────────
// The pinned tokens the module reports now (client.tokenPins(): the C
// module's one table, checked by nodusTokens); [] for a module without the
// token group.
export function pinnedTokens(client) {
  return client?.tokenable === true ? nodusTokens(client.tokenPins()) : [];
}
// The asset a NODUS send is for, from its token id: { native: true } for the
// all-zero id, { native: false, pin } for a pinned token. Throws for a missing
// or malformed id (NO hop defaults to native, §6 item 1) and for a token the
// module does not pin ("Yalnız tUSDT").
function sendAsset(client, tokenId) {
  if (typeof tokenId !== 'string' || !HEX128.test(tokenId)) throw new Error('Choose the asset to send.');
  if (tokenId === NODUS_TOKEN_ID) return { native: true, tokenId, symbol: NODUS_ASSET.symbol, decimals: DECIMALS };
  const pin = pinnedTokens(client).find(p => p.tokenId === tokenId);
  if (!pin) throw new Error('This token is not supported by this wallet.');
  // metadata that does not equal the pin (operator "tUSDT'yi kapat")
  if (!pin.available) throw new Error(`${pin.symbol} is unavailable right now. Nothing was sent.`);
  return { native: false, ...pin };
}
// One pinned token's row of the module's balance answer: { total, spendable }
// as BigInt, or null when the answer has no such row / an invalid one. The
// module reports a row for every pin (an owner holding none is a real zero);
// no row is NOT a zero.
export function tokenBalanceOf(result, tokenId) {
  const row = Array.isArray(result?.tokens) ? result.tokens.find(t => t?.tokenId === tokenId) : undefined;
  if (!row) return null;
  try {
    const total = rawUnits(row.total, 'balance'), spendable = rawUnits(row.spendable, 'balance');
    return spendable > total ? null : { total, spendable };
  } catch { return null; }
}
// The pinned tokens' coins of a listing, for ONE token: [{ nullifier, amount
// }] after the same checks as parseCoins, and whether the module read that
// token's coin list at all (`listed` — a node that ignores the token filter,
// or a failed read, leaves it false: never a list of another token's coins).
export function parseTokenCoins(listing, tokenId) {
  const invalid = () => new Error('The Nodus module returned an invalid coin list.');
  const rows = Array.isArray(listing?.tokenCoins) ? listing.tokenCoins : [];
  if (rows.length > MAX_LISTED_COINS) throw invalid();
  const seen = new Set();
  const coins = rows.filter(coin => {
    if (!coin || typeof coin.nullifier !== 'string' || !HEX128.test(coin.nullifier) || typeof coin.tokenId !== 'string' || !HEX128.test(coin.tokenId) || seen.has(coin.nullifier)) throw invalid();
    seen.add(coin.nullifier);
    if (rawUnits(coin.amount, 'coin amount') === 0n) throw invalid();
    return coin.tokenId === tokenId;
  }).map(coin => ({ nullifier: coin.nullifier, amount: coin.amount }));
  const status = Array.isArray(listing?.tokens) ? listing.tokens.find(t => t?.tokenId === tokenId) : undefined;
  return { coins, listed: status?.listed === true, truncated: status?.truncated === true };
}
// Everything shown on the review screen comes from here: the module's own
// decoding of the envelope it signed. Anything malformed stops the send.
export function decodeBuilt(built) {
  const d = built?.decoded;
  if (!built || !(built.envelope instanceof Uint8Array) || built.envelope.length === 0 || typeof built.intentId !== 'string' || !HEX128.test(built.intentId) || !d) throw new Error('The Nodus module returned an invalid transaction.');
  if (typeof d.recipient !== 'string' || !HEX128.test(d.recipient) || typeof d.chainId !== 'string' || !HEX64.test(d.chainId)) throw new Error('The Nodus module returned an invalid transaction.');
  if (!Array.isArray(d.inputs) || d.inputs.length < 1 || d.inputs.length > NODUS_MAX_INPUTS || new Set(d.inputs).size !== d.inputs.length || !d.inputs.every(input => typeof input === 'string' && HEX128.test(input))) throw new Error('The Nodus module returned an invalid transaction.');
  // The token the bytes pay (128 hex, all zeros = NODUS) and its change are
  // REQUIRED: a module that does not report them is refused, never read as
  // NODUS (§6 item 1: no hop defaults to native).
  if (typeof d.tokenId !== 'string' || !HEX128.test(d.tokenId)) throw new Error('The Nodus module returned an invalid transaction.');
  return {
    envelope: built.envelope, intentId: built.intentId, recipient: d.recipient, chainId: d.chainId, inputs: [...d.inputs],
    amount: rawUnits(d.amount, 'transaction amount'), fee: rawUnits(d.fee, 'network fee'), change: rawUnits(d.change, 'change amount'),
    tokenId: d.tokenId, tokenChange: rawUnits(d.tokenChange, 'token change amount'),
    expiryHeight: rawUnits(d.expiryHeight, 'expiry height'), ...builtWire(built)
  };
}
const nodusText = units => `${formatUnits(units, DECIMALS)} ${NODUS_ASSET.symbol}`;

// Portfolio balance read (src/portfolio-view.js readBalances): the spendable
// native balance, then one row per pinned token. Any failure of the read
// throws, which the portfolio shows as "Balance unavailable" — never as zero
// (design G5); a token the node's metadata does not confirm gets a row of its
// own that says so (`unavailable`, "Unavailable right now"), and one whose
// balance row is missing or invalid an error row — neither touches the NODUS
// row. (An address holding more than 256 token kinds makes the node refuse
// the whole answer, and with it this read: no balance, never a zero.)
export async function balances(chain, address, _endpoint, { signal, client } = {}) {
  if (chain !== NODUS_ASSET.chain || !client || client.state !== 'ready') throw new Error('Nodus connection is not ready.');
  if (address !== client.fingerprint) throw new Error('Nodus address does not match the connected identity.');
  const result = await client.balance({ signal });
  const { spendable } = parseBalance(result);
  const rows = [{ symbol: NODUS_ASSET.symbol, balance: formatUnits(spendable, DECIMALS) }];
  for (const pin of pinnedTokens(client)) {
    const row = pin.available ? tokenBalanceOf(result, pin.tokenId) : null;
    rows.push(!pin.available ? { symbol: pin.symbol, error: true, unavailable: true }
      : row ? { symbol: pin.symbol, balance: formatUnits(row.spendable, pin.decimals) } : { symbol: pin.symbol, error: true });
  }
  return rows;
}

// Builds and signs one SPEND for review. `locked`: coins of pending sends
// (lockedInputs). `inputs`: a resend's exact coins (resendInputs), else null.
// `tokenId` (REQUIRED, 128 hex; all zeros = NODUS): the asset being sent — the
// send form's identity, never a symbol (design 2026-10-22-connect-native-
// tokens-design.md §6 item 1). A pinned token is sent through the module's
// token build; its amount is in that token's decimals.
export async function prepare({ client, from, to, amount, tokenId, locked = new Set(), inputs = null }) {
  if (!client || client.state !== 'ready') throw new Error('Nodus sending is not available right now.');
  if (from !== client.fingerprint) throw new Error('Nodus address does not match the connected identity.');
  const asset = sendAsset(client, tokenId);
  const units = asset.native ? nodusAmountUnits(amount) : (() => {
    const value = amountUnits(typeof amount === 'string' ? amount.trim() : amount, asset.decimals);
    if (value > U64_MAX) throw new Error('Amount is out of range.');
    return value;
  })();
  // A chain name resolves to its owner first (one node, decision item 9).
  const { recipient, resolved } = await resolveNodusRecipient(client, to);
  const balanceAnswer = await client.balance();
  const { spendable } = parseBalance(balanceAnswer);
  const listing = await client.list();
  const coins = parseCoins(listing);
  // A read error on the node answers "0 coins" (design §1.4); with a positive
  // spendable balance, an empty list is a read failure, not "insufficient".
  if (coins.length === 0 && spendable > 0n) throw new Error('Your coin list could not be read. Nothing was sent; try again later.');
  // A token send: the token's own balance and coin list, read the same way
  // ("coin list unavailable" for a node that ignores the token filter —
  // never a zero, never another token's coins).
  let tokenCoins = [], tokenSpendable = 0n;
  if (!asset.native) {
    const held = tokenBalanceOf(balanceAnswer, asset.tokenId);
    if (!held) throw new Error(`Your ${asset.symbol} balance could not be read. Nothing was sent; try again later.`);
    tokenSpendable = held.spendable;
    const listed = parseTokenCoins(listing, asset.tokenId);
    if (!listed.listed) throw new Error(`The ${asset.symbol} coin list is unavailable right now. Nothing was sent; try again later.`);
    tokenCoins = listed.coins;
    if (tokenCoins.length === 0 && tokenSpendable > 0n) throw new Error(`Your ${asset.symbol} coin list could not be read. Nothing was sent; try again later.`);
  }
  // HF-4: which rules the node runs, then the expiry they allow.
  const ruleset = parseRulesetInfo(await client.rulesetInfo());
  const tip = parseTip(listing.tip), expiryHeight = expiryHeightFor(tip, ruleset);
  let candidates;
  if (inputs) {
    const listed = new Map([...coins, ...tokenCoins].map(coin => [coin.nullifier, coin]));
    if (!inputs.every(input => listed.has(input))) throw new Error('The coins of the earlier send are no longer listed. Check its status before sending again.');
    candidates = inputs.map(input => listed.get(input));
  } else {
    const free = list => list.filter(coin => !locked.has(coin.nullifier));
    candidates = free(coins);
    if (candidates.length === 0) throw new Error(locked.size ? 'Your coins are held by a pending send. Wait for it to be included or to expire.' : asset.native ? 'Insufficient NODUS balance.' : 'Not enough NODUS for the network fee.');
    if (!asset.native) {
      const tokenCandidates = free(tokenCoins);
      if (tokenCandidates.reduce((sum, coin) => sum + BigInt(coin.amount), 0n) < units) throw new Error(locked.size && tokenSpendable >= units ? 'Your coins are held by a pending send. Wait for it to be included or to expire.' : `Not enough ${asset.symbol}.`);
      candidates = [...candidates, ...tokenCandidates];
    }
  }
  const request = { to: recipient, amount: units.toString(), expiryHeight: expiryHeight.toString(), coins: candidates };
  const decoded = decodeBuilt(await (asset.native ? client.buildAndSign({ ...request, tokenId: asset.tokenId }) : client.tokenBuildAndSign({ ...request, tokenId: asset.tokenId })));
  // The signed envelope must be exactly what was requested — the TOKEN too
  // (§6 item 1: prepare() refuses when decoded.token differs from the
  // requested one) — or nothing is shown.
  if (decoded.recipient !== recipient || decoded.amount !== units || decoded.tokenId !== asset.tokenId || decoded.expiryHeight !== expiryHeight || decoded.chainId !== client.chainId) throw new Error('The signed transaction does not match your request. Nothing was sent.');
  if (asset.native && decoded.tokenChange !== 0n) throw new Error('The signed transaction does not match your request. Nothing was sent.');
  const allowed = new Set(candidates.map(coin => coin.nullifier));
  if (!decoded.inputs.every(input => allowed.has(input))) throw new Error('The signed transaction uses coins it may not use. Nothing was sent.');
  const amountText = `${formatUnits(decoded.amount, asset.decimals)} ${asset.symbol}`;
  const review = [
    ['Network', 'Nodus'],
    ['From', from],
    ...(resolved ? nameReviewRows(resolved, { showOwner: false }) : []),
    ['To', decoded.recipient],
    resolved ? [...NAME_CHECK_ROW] : ['Address check', 'Nodus addresses have no checksum. Compare all 128 characters with your source.'],
    ['Amount', amountText],
    ['Network fee', nodusText(decoded.fee)],
    // a token send names both changes: the token's and the NODUS one
    ...(asset.native ? [['Change back to you', nodusText(decoded.change)]]
      : [[`${asset.symbol} change back to you`, `${formatUnits(decoded.tokenChange, asset.decimals)} ${asset.symbol}`], ['NODUS change back to you', nodusText(decoded.change)]]),
    ['Valid until block', decoded.expiryHeight.toString()],
    ...expiryCapRows(tip, decoded.expiryHeight, ruleset),
    ['Chain ID', decoded.chainId],
    ['Fee note', 'The network fee may be charged even if the transfer fails.']
  ];
  if (listing.truncated === true || (!asset.native && parseTokenCoins(listing, asset.tokenId).truncated)) review.push(['Coin list', 'Your coin list may be incomplete; the transfer uses only the coins listed.']);
  let used = false;
  return {
    to: decoded.recipient, recipientName: resolved?.name, amount: formatUnits(decoded.amount, asset.decimals), symbol: asset.symbol, tokenId: asset.tokenId, fee: nodusText(decoded.fee),
    // Review-dialog timeout only (UI). The envelope's own validity is its
    // expiry height, checked by the chain.
    expiresAt: Date.now() + NODUS_REVIEW_MS,
    intentId: decoded.intentId, expiryHeight: decoded.expiryHeight.toString(), review,
    // onBroadcast must make the pending-send record durable BEFORE the envelope
    // leaves the browser (the same rule as the other networks, src/app.js).
    async send(onBroadcast) {
      if (used) throw new Error('This review is already closed.');
      used = true;
      await onBroadcast({ hash: decoded.intentId, expiryHeight: decoded.expiryHeight.toString(), fromHeight: (tip + 1n).toString(), inputs: [...decoded.inputs], ...(decoded.wire ? { wire: decoded.wire } : {}) });
      await submitSigned(client, decoded.envelope, decoded.intentId, () => 'The Nodus network did not accept this transfer. Its coins stay held until the transfer expires.');
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
    // `block`: the inclusion height, for the status line after a submission
    // (src/activity.js submissionStatus); src/activity-storage.js does not keep it.
    return { status: 'confirmed', block: height.toString(), note: claim ? `Allocation claimed in block ${height} (reported by one Nodus node).` : `Included in block ${height} (reported by one Nodus node).` };
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

// ── Staking (0.1.29) ──────────────────────────────────────────────────────
// The module side is nodus-cli `v2-envelope stake | delegate | undelegate`
// over the shared builder (crypto/nodus-send-wasm.c "STAKING"); this side
// validates what crosses the boundary, pre-checks the chain rules that need
// the listed state (the builder cannot see it), and builds the review from
// the module's own read-back of the signed envelope (G1).
// Sources of the rules: nodus/src/witness/nodus_witness_rt_native.c
// rtn_delegate_exec (a target that is bonded — ACTIVE or ELIGIBLE —, at
// least the minimum for a NEW delegation, any amount >= 1 to top one up),
// rtn_undelegate_exec (amount <= the delegation, a partial withdrawal
// leaves 0 or at least the minimum), rtn_stake_exec (exactly the
// self-bond, commission <= the maximum, no second bond unless the row is
// UNSTAKED), rtn_sysfund_release_coin (the returned coin is locked until
// the power-exit boundary + DNAC_UNDELEGATE_LOCK_EPOCHS epochs).
export const VALIDATOR_STATUS = Object.freeze(['active', 'retiring', 'unstaked', 'auto-retired', 'eligible']);
const STATUS_TEXT = { active: 'Active', retiring: 'Leaving', unstaked: 'Stopped', 'auto-retired': 'Stopped (was not taking part)', eligible: 'Waiting for a seat' };
const RATE = bps => `${(bps / 100).toFixed(2).replace(/\.?0+$/, '')}%`;
export function parseStakingRules(rules) {
  const invalid = () => new Error('Staking is not available in this wallet version.');
  if (!rules) throw invalid();
  const out = {};
  for (const key of ['minDelegation', 'selfStake', 'commissionMaxBps', 'undelegateLockEpochs', 'epochLength', 'maxDelegators']) {
    out[key] = rawUnits(rules[key], 'staking rule');
    if (out[key] === 0n) throw invalid();
  }
  if (out.commissionMaxBps > 10000n) throw invalid();
  return out;
}
export function parseValidators(result) {
  const invalid = () => new Error('The Nodus module returned an invalid witness list.');
  if (!result || typeof result.truncated !== 'boolean' || !Array.isArray(result.validators) || result.validators.length > 256) throw invalid();
  const seen = new Set();
  const validators = result.validators.map(v => {
    if (!v || typeof v.fingerprint !== 'string' || !HEX128.test(v.fingerprint) || seen.has(v.fingerprint) || !Number.isInteger(v.commissionBps) || v.commissionBps < 0 || v.commissionBps > 10000 || !Number.isInteger(v.status) || v.status < 0 || v.status >= VALIDATOR_STATUS.length) throw invalid();
    // delegators: filled delegator slots, or null = unknown (an older node
    // answers no count: the module reports -1, or the field is absent) —
    // never shown as 0.
    if (v.delegators !== undefined && v.delegators !== -1 && (!Number.isInteger(v.delegators) || v.delegators < 0)) throw invalid();
    seen.add(v.fingerprint);
    const status = VALIDATOR_STATUS[v.status];
    const delegators = v.delegators === undefined || v.delegators === -1 ? null : v.delegators;
    // HF-6 (send-module.js validators): a generation-4 row's validator_id
    // and owner — both 128 hex and not all zero when hasV2, '' otherwise. A
    // module or node without them (hasV2 absent / false): '' for both.
    const hasV2 = v.hasV2 === true;
    const validatorId = hasV2 ? v.validatorId : '', ownerFp = hasV2 ? v.ownerFp : '';
    if (hasV2 && ![validatorId, ownerFp].every(id => typeof id === 'string' && HEX128.test(id) && id !== ZERO128)) throw invalid();
    if (hasV2) { if (seen.has(`vid:${validatorId}`)) throw invalid(); seen.add(`vid:${validatorId}`); }
    return { fingerprint: v.fingerprint, selfStake: rawUnits(v.selfStake, 'witness stake'), delegated: rawUnits(v.delegated, 'witness stake'), commissionBps: v.commissionBps, status, statusText: STATUS_TEXT[status], acceptsDelegation: status === 'active' || status === 'eligible', delegators, hasV2, validatorId, ownerFp };
  });
  return { truncated: result.truncated, validators };
}
export function parseDelegations(rows) {
  const invalid = () => new Error('The Nodus module returned an invalid delegation list.');
  if (!Array.isArray(rows) || rows.length > 256) throw invalid();
  const seen = new Set();
  return rows.map(row => {
    if (!row || typeof row.validator !== 'string' || !HEX128.test(row.validator) || seen.has(row.validator)) throw invalid();
    seen.add(row.validator);
    const amount = rawUnits(row.amount, 'delegation amount');
    if (amount === 0n) throw invalid();
    return { validator: row.validator, amount, block: rawUnits(row.block, 'block height') };
  });
}
function stakeReady(client, from) {
  if (!client || client.state !== 'ready' || !client.stakeable) throw new Error('Staking is not available right now.');
  if (from !== client.fingerprint) throw new Error('Nodus address does not match the connected identity.');
}
export const shortKey = fp => `${fp.slice(0, 8)}…${fp.slice(-8)}`;
// The validator list, this wallet's delegations (joined with the list: a
// delegation whose validator is not listed cannot be undelegated from here —
// the module needs the validator's list row) and whether this wallet is
// itself a validator (its own fingerprint listed with any status but
// 'unstaked').
// HF-6 slice 7b: under generation 4 the node names a delegation's validator
// by its validator_id, not its key fingerprint (nodus_witness_handlers.c
// dlg_v2_reply: "validator" = hex(validator_id)); a generation-4 list row
// carries that id (validatorId, hasV2). A row is joined by the id first,
// then by the fingerprint (the legacy reply), and a joined row's
// `validator` becomes the list row's FINGERPRINT — the one name the page
// and prepareStake use for a witness — with the node's own value kept in
// `listedAs`. An unjoined row keeps the node's value in both.
export async function stakingOverview({ client, from, signal } = {}) {
  stakeReady(client, from);
  const rules = parseStakingRules(client.stakingRules);
  const { truncated, validators } = parseValidators(await client.validators({ signal }));
  const delegations = parseDelegations(await client.delegations({ signal }));
  const byKey = new Map(validators.map(v => [v.fingerprint, v]));
  const byId = new Map(validators.filter(v => v.hasV2).map(v => [v.validatorId, v]));
  const own = byKey.get(from);
  const joined = delegations.map(row => {
    const info = byId.get(row.validator) ?? byKey.get(row.validator);
    return { ...row, validator: info ? info.fingerprint : row.validator, listedAs: row.validator, validatorInfo: info, canUndelegate: info !== undefined };
  });
  // two delegations joined to one witness (an id and a key naming the same
  // row) would make "your delegation" ambiguous: refused, never merged
  if (new Set(joined.map(row => row.validator)).size !== joined.length) throw new Error('The Nodus module returned an invalid delegation list.');
  return {
    rules, truncated, validators,
    delegations: joined,
    ownValidator: own && own.status !== 'unstaked' ? own : undefined,
    network: networkStake(validators, truncated),
    lockText: `${rules.undelegateLockEpochs} epochs (${rules.undelegateLockEpochs} × ${rules.epochLength} = ${rules.undelegateLockEpochs * rules.epochLength} blocks)`
  };
}
// The network's total stake (operator 2026-10-12: "Total network'taki stack
// durumunu görebiliyor muyuz?" — "Ekle"), summed from the same witness list
// Earn shows, by Scan's rule (explorer/src/exp_http.c "Staking"): only the
// BONDED witnesses — status active or eligible — count; their bonds
// (selfStake) and the NODUS delegated to them (delegated, self-delegations
// included). `partial`: the node listed only the first witnesses, so the sum
// is a lower bound.
export function networkStake(validators, truncated) {
  let witnesses = 0, selfStake = 0n, delegated = 0n;
  for (const v of validators) {
    if (v.status !== 'active' && v.status !== 'eligible') continue;
    witnesses++; selfStake += v.selfStake; delegated += v.delegated;
  }
  return { witnesses, selfStake, delegated, total: selfStake + delegated, partial: truncated === true };
}
// The module's read-back of a staking envelope, checked for shape.
function decodeStake(built) {
  const d = built?.decoded, invalid = () => new Error('The Nodus module returned an invalid transaction.');
  if (!built || !(built.envelope instanceof Uint8Array) || built.envelope.length === 0 || typeof built.intentId !== 'string' || !HEX128.test(built.intentId) || !d) throw invalid();
  if (!['stake', 'delegate', 'undelegate'].includes(d.op) || typeof d.validator !== 'string' || !HEX128.test(d.validator) || typeof d.chainId !== 'string' || !HEX64.test(d.chainId)) throw invalid();
  if (!Array.isArray(d.inputs) || d.inputs.length < 1 || d.inputs.length > NODUS_MAX_INPUTS || new Set(d.inputs).size !== d.inputs.length || !d.inputs.every(input => typeof input === 'string' && HEX128.test(input))) throw invalid();
  // the generation-4 call's validator_id (send-module.js stakeBuild): ''
  // below generation 4 and for stake, else 128 hex, never all zero
  const validatorId = d.validatorId === undefined ? '' : d.validatorId;
  if (typeof validatorId !== 'string' || (validatorId !== '' && (!HEX128.test(validatorId) || validatorId === ZERO128))) throw invalid();
  return {
    envelope: built.envelope, intentId: built.intentId, op: d.op, validator: d.validator, validatorId, chainId: d.chainId, inputs: [...d.inputs],
    amount: rawUnits(d.amount, 'transaction amount'), commissionBps: rawUnits(d.commissionBps, 'commission'), fee: rawUnits(d.fee, 'network fee'),
    change: rawUnits(d.change, 'change amount'), expiryHeight: rawUnits(d.expiryHeight, 'expiry height'), ...builtWire(built)
  };
}
// A STAKE from Earn under the HF-6 generation: its layout needs the node's
// consent, built only on the Nodus Connect "Nodus" page (prepareHf6). The
// module refuses it with the same text (nodus-send-wasm.c
// NSW_STAKE_NEEDS_CONSENT).
export const HF6_STAKE_CONSENT_TEXT = 'Becoming a witness now needs your node\'s consent. Open Nodus Connect → More → Nodus.';
// Builds and signs one staking envelope for review, in the shape of
// prepareClaim (cancel(), confirm(onBroadcast) usable once, refused after
// expiresAt). kind: 'delegate' | 'undelegate' | 'stake'. Under the HF-6
// generation a delegate / undelegate is built in its generation-4 layout
// by the module (the validator's id taken from the same list row as its
// key); a 'stake' is refused (HF6_STAKE_CONSENT_TEXT). `validator`: 128
// hex (delegate / undelegate). `amount`: NODUS text (delegate /
// undelegate; stake always bonds exactly the self-bond). `commissionBps`:
// integer text (stake). `locked`: coins of pending NODUS transactions
// (lockedInputs) — never offered to the builder.
export async function prepareStake({ client, from, kind, validator, amount, commissionBps, locked = new Set() } = {}) {
  stakeReady(client, from);
  if (!['delegate', 'undelegate', 'stake'].includes(kind)) throw new Error('Unknown staking action.');
  // Fresh lists: the module resolves the validator's key from ITS last
  // listing, and the rules below read the current rows.
  const view = await stakingOverview({ client, from });
  const { rules } = view;
  let units, target, commission = 0n, existing;
  if (kind === 'stake') {
    if (view.ownValidator) throw new Error('This wallet is already a witness.');
    units = rules.selfStake;
    if (typeof commissionBps !== 'string' || !/^(0|[1-9]\d{0,4})$/.test(commissionBps)) throw new Error('Enter a commission between 0% and 50%.');
    commission = BigInt(commissionBps);
    if (commission > rules.commissionMaxBps) throw new Error(`The commission can be at most ${RATE(Number(rules.commissionMaxBps))}.`);
    target = from;
  } else {
    target = typeof validator === 'string' ? validator : '';
    if (!HEX128.test(target)) throw new Error('Choose a witness.');
    units = nodusAmountUnits(amount);
    if (units === 0n) throw new Error('Enter an amount above zero.');
    existing = view.delegations.find(row => row.validator === target);
    const info = view.validators.find(v => v.fingerprint === target);
    if (kind === 'delegate') {
      if (!info) throw new Error('This witness is not in the current witness list.');
      if (!info.acceptsDelegation) throw new Error(`This witness does not accept delegations now (${info.statusText}).`);
      if (!existing && units < rules.minDelegation) throw new Error(`A new delegation must be at least ${formatUnits(rules.minDelegation, DECIMALS)} NODUS.`);
      // The chain admits a NEW delegator only below the per-validator cap; a
      // top-up of an existing delegation is exempt (nodus_witness_rt_native.c
      // rtn_delegate_exec: `!dr->present && count >= cap` refuses). Checked
      // only when the node reported the count (null = unknown: the chain decides).
      if (!existing && info.delegators !== null && BigInt(info.delegators) >= rules.maxDelegators) throw new Error(`This witness already has the most delegators it can take (${info.delegators}/${rules.maxDelegators}). Choose another witness.`);
    } else {
      if (!existing) throw new Error('You have no delegation with this witness.');
      if (!info) throw new Error('This witness is not in the current witness list, so its delegation cannot be withdrawn from here.');
      if (units > existing.amount) throw new Error(`You can withdraw at most ${nodusText(existing.amount)}.`);
      const rest = existing.amount - units;
      if (rest !== 0n && rest < rules.minDelegation) throw new Error(`Withdraw everything, or leave at least ${formatUnits(rules.minDelegation, DECIMALS)} NODUS delegated.`);
    }
  }
  const { spendable } = parseBalance(await client.balance());
  const listing = await client.list();
  const coins = parseCoins(listing);
  if (coins.length === 0 && spendable > 0n) throw new Error('Your coin list could not be read. Nothing was sent; try again later.');
  // HF-4: which rules the node runs, then the expiry they allow.
  const ruleset = parseRulesetInfo(await client.rulesetInfo());
  // The module refuses this too (it is the authority: it asks the node again
  // when it builds); a module without hf6Rules leaves it to the module.
  const hf6Generation = client.hf6Rules && Number.isSafeInteger(client.hf6Rules.generation) && client.hf6Rules.generation >= 1 ? BigInt(client.hf6Rules.generation) : null;
  if (kind === 'stake' && hf6Generation !== null && ruleset.generation >= hf6Generation) throw new Error(HF6_STAKE_CONSENT_TEXT);
  const tip = parseTip(listing.tip), expiryHeight = expiryHeightFor(tip, ruleset);
  const candidates = coins.filter(coin => !locked.has(coin.nullifier));
  if (candidates.length === 0) throw new Error(locked.size ? 'Your coins are held by a pending transaction. Wait for it to be included or to expire.' : 'Insufficient NODUS balance.');
  const d = decodeStake(await client.stakeBuild({ op: kind, validator: kind === 'stake' ? '' : target, amount: units.toString(), commissionBps: commission.toString(), expiryHeight: expiryHeight.toString(), coins: candidates }));
  // The signed envelope must be exactly what was requested, or nothing is shown.
  if (d.op !== kind || d.validator !== target || d.amount !== units || d.commissionBps !== commission || d.expiryHeight !== expiryHeight || d.chainId !== client.chainId) throw new Error('The signed transaction does not match your request. Nothing was sent.');
  const amounts = new Map(candidates.map(coin => [coin.nullifier, BigInt(coin.amount)]));
  if (!d.inputs.every(input => amounts.has(input))) throw new Error('The signed transaction uses coins it may not use. Nothing was sent.');
  const inSum = d.inputs.reduce((sum, input) => sum + amounts.get(input), 0n);
  const lock = kind === 'undelegate' ? 0n : d.amount;
  if (inSum !== lock + d.fee + d.change) throw new Error('The signed transaction does not add up. Nothing was sent.');
  const info = view.validators.find(v => v.fingerprint === target);
  // BUGS W-19 (design hf5 rev 6 §9: "Cüzdan Earn validator_id'yi hedefler"):
  // under generation 4 a delegate / undelegate call names its witness ONLY
  // by validator_id — that is the witness the chain credits. It must be the
  // id of the row the user chose (the same list row whose key fingerprint
  // `validator` is); below generation 4, and for a stake, the call carries
  // none. When the module carries no hf6Rules the generation is not known
  // here: an id must then still be the row's. What this does NOT check:
  // that the row's id belongs to the row's key (a node could list A's key
  // with B's id in one row) — the Review shows the signed id so the user can
  // compare it; the key↔id derivation check is a separate decision.
  const gen4 = kind === 'stake' ? false : hf6Generation !== null ? ruleset.generation >= hf6Generation : null;
  const rowId = info && info.hasV2 ? info.validatorId : null;
  const idOk = d.validatorId === '' ? gen4 !== true : gen4 !== false && rowId !== null && d.validatorId === rowId;
  if (!idOk) throw new Error('The signed transaction does not match your request. Nothing was sent.');
  const witnessRows = d.validatorId ? [['Witness', d.validator], ['Witness ID', d.validatorId]] : [['Witness', d.validator]];
  const review = [['Network', 'Nodus testnet']];
  if (kind === 'delegate') {
    review.push(['Action', 'Delegate NODUS'], ...witnessRows, ['Witness commission', info ? RATE(info.commissionBps) : '—'],
      ['Amount', nodusText(d.amount)], ['Network fee', nodusText(d.fee)], ['Change back to you', nodusText(d.change)],
      ['Note', `The delegated NODUS stays yours but is held with this witness and cannot be sent while delegated. To get it back you undelegate; it then returns to you locked for ${view.lockText} after the witness set changes.`]);
  } else if (kind === 'undelegate') {
    review.push(['Action', 'Undelegate NODUS'], ...witnessRows, ['Amount returned to you', nodusText(d.amount)],
      ['Network fee', `${nodusText(d.fee)} (paid from your spendable NODUS)`], ['Change back to you', nodusText(d.change)],
      ['Lock', `The returned NODUS arrives as a separate coin at your address. It stays locked for ${view.lockText} after the witness set next changes; until then it cannot be sent or delegated again.`]);
  } else {
    review.push(['Action', 'Become a witness'], ['Bond', nodusText(d.amount)], ['Commission', RATE(Number(d.commissionBps))],
      ['Bond returns to', `${from} (your own address)`], ['Network fee', nodusText(d.fee)], ['Change back to you', nodusText(d.change)],
      ['Important', 'The bond stays locked while you are a witness. This wallet has no way to unstake it: there is no leave-the-witness-set action here. An active witness is expected to take part in producing blocks; one that does not is retired automatically.']);
  }
  review.push(['Valid until block', d.expiryHeight.toString()], ...expiryCapRows(tip, d.expiryHeight, ruleset), ['Chain ID', d.chainId], ['Fee note', 'The network fee may be charged even if the transaction fails.']);
  if (listing.truncated === true) review.push(['Coin list', 'Your coin list may be incomplete; only the coins listed are used.']);
  let used = false;
  const expiresAt = Date.now() + NODUS_REVIEW_MS;
  return {
    kind, chain: NODUS_ASSET.chain, from, to: d.validator, symbol: NODUS_ASSET.symbol, amount: formatUnits(d.amount, DECIMALS),
    endpoint: undefined, fee: nodusText(d.fee), expiresAt, review, intentId: d.intentId,
    cancel() { used = true; },
    async confirm(onBroadcast) {
      if (used) throw new Error('This review is already closed.');
      used = true; // an ambiguous submission is never retried automatically
      if (Date.now() >= expiresAt) throw new Error('Review expired. Prepare it again.');
      // The record is durable before the envelope leaves the browser; its
      // inputs are held like a send's (lockedInputs) until it resolves.
      await onBroadcast({ hash: d.intentId, expiryHeight: d.expiryHeight.toString(), fromHeight: (tip + 1n).toString(), inputs: [...d.inputs], ...(d.wire ? { wire: d.wire } : {}) });
      await submitSigned(client, d.envelope, d.intentId, result => `The Nodus network did not accept this transaction. Its coins stay held until it expires.${refusalDetail(result)}`);
      return d.intentId;
    }
  };
}

// ── HF-6: become a witness, become a storage node, leave storage, stop
//    being a witness (Nodus Connect "Nodus" page, src/nodus-roles.js) ─────
// Design docs/plans/2026-10-12-connect-hf6-screens-design.md rev 1 (§2 the
// consent checks, §3 the gates, G1-G4); docs/plans/2026-10-03-hf5-
// validator-owner-stake-design.md rev 6 §6.1, §9, §11. No key rotation:
// the khan removed ROTATE from HF-6 (decision 2026-10-13-kurultay-18-
// summary.md item 1). The module side is nodus-cli `v2-envelope stake2 |
// unstake` and `storage register | exit`
// over the shared builder (crypto/nodus-send-wasm.c "HF-6: NODE CONSENT"):
// it re-checks the consent with this wallet's own fingerprint, the pinned
// chain and the coin listing's tip, and builds nothing below the HF-6
// generation. This side checks what crosses the boundary, applies the gates
// the page shows (generation, balance) and keeps the module's read-back of
// the signed envelope — the only values the Review shows (G3).
// The owner is always THIS wallet's own key (a single-key owner, kind 1):
// a shared vault (multisig) owner is not built by any builder yet (design
// §3) and is never offered.
export const HF6_KINDS = Object.freeze(['stake', 'storageRegister', 'storageExit', 'unstake']);
// The amber note of design §3 (operator 2026-10-12: the screens are shown
// before HF-6 is in force; sending stays disabled until then).
export const HF6_NOT_YET_TEXT = 'Before the network upgrade that opens these roles, these screens show what they will do but cannot send.';
// dnac_storage_status "st" (nodus/include/nodus/nodus.h): 1 ACTIVE,
// 2 EXITING, 3 RELEASED.
export const STORAGE_STATUS = Object.freeze({ 1: 'active', 2: 'leaving', 3: 'released' });
const STORAGE_STATUS_TEXT = Object.freeze({ active: 'Storing', leaving: 'Leaving', released: 'Left' });
const CONSENT_CHECK_IDS = Object.freeze(['format', 'op', 'chain', 'owner', 'subject', 'expiry', 'signature']);
// A consent whose expiry is before the transaction's own last valid block
// (both BigInt): included after the consent's block, the network refuses the
// transaction — so it is refused before anything is built (BUGS W-21; the
// page shows the same text as a failed check, src/nodus-roles.js).
export const CONSENT_ENDS_EARLY_TEXT = 'This consent expires before this transaction could be included; make a new consent on the node.';
export function consentEndsBefore(consentExpiry, expiryHeight) {
  return typeof consentExpiry === 'bigint' && typeof expiryHeight === 'bigint' && consentExpiry < expiryHeight;
}
// The module's hf6Rules (src/nodus/client.js validHf6Rules), as BigInt;
// the three timing multipliers are null when the module does not carry them.
// The two bonds are not here: they are chain parameters (hf6Bonds below).
export function parseHf6Rules(rules) {
  const invalid = () => new Error('Witness and storage roles are not available in this wallet version.');
  if (!rules || !Number.isSafeInteger(rules.generation) || rules.generation < 1) throw invalid();
  const out = { generation: BigInt(rules.generation), consentWindow: rawUnits(rules.consentWindow, 'network rule') };
  if (out.consentWindow === 0n) throw invalid();
  for (const key of ['minTenureBlocks', 'storageExitLockEpochs', 'validatorUnbondEpochs']) out[key] = rules[key] === undefined ? null : rawUnits(rules[key], 'network rule');
  return out;
}
function hf6Ready(client, from) {
  if (!client || client.state !== 'ready' || !client.hf6able) throw new Error('Witness and storage roles are not available right now.');
  if (from !== client.fingerprint) throw new Error('Nodus address does not match the connected identity.');
}
// The module's hf6Bonds() answer (send-module.js; nodus-send-wasm.c
// nsw_hf6_bonds), as BigInt: stakeMin — the witness bond floor, storageBond
// — the exact storage bond, both in force at the node's tip + 1 (chain
// parameters 19 / 21, BUGS W-20). The module already resolved an older
// node's 0 to the compiled default and refused a value outside the
// network's range; here only the shape (raw decimal above 0) is checked.
export function parseHf6Bonds(result) {
  const invalid = () => new Error('The Nodus module returned invalid bond amounts.');
  if (!result) throw invalid();
  const stakeMin = rawUnits(result.stakeMin, 'witness bond'), storageBond = rawUnits(result.storageBond, 'storage bond');
  if (stakeMin === 0n || storageBond === 0n) throw invalid();
  return { stakeMin, storageBond };
}
// The two role bonds the connected node reports (ONE node's answer).
export async function hf6Bonds({ client, from, signal } = {}) {
  hf6Ready(client, from);
  return parseHf6Bonds(await client.hf6Bonds({ signal }));
}
// The consent checks of design §2, run by the module (synchronous, no
// network) against this wallet's own fingerprint, the pinned chain and
// `tip` (BigInt, the block height last read). kind: 'stake' |
// 'storageRegister'. Resolves
// { ok, checks: [{ id, ok, detail }] × 7, nodeFp ('' if the text did not
// parse), expiry (BigInt | null) } — the module's own lines, checked for
// shape. `ok` only when every line passed.
export function checkConsent({ client, from, kind, text, tip } = {}) {
  if (!client || !client.identified) throw new Error('Nodus connection is not ready.');
  if (from !== client.fingerprint) throw new Error('Nodus address does not match the connected identity.');
  if (!['stake', 'storageRegister'].includes(kind)) throw new Error('Unknown consent action.');
  if (typeof tip !== 'bigint') throw new Error('The current Nodus block height is unknown.');
  const r = client.consentCheck({ op: kind, text, tip: tip.toString() });
  const invalid = () => new Error('The Nodus module returned an invalid consent check.');
  if (!r || typeof r.ok !== 'boolean' || !Array.isArray(r.checks) || r.checks.length !== CONSENT_CHECK_IDS.length) throw invalid();
  const checks = r.checks.map((line, i) => {
    if (!line || line.id !== CONSENT_CHECK_IDS[i] || typeof line.ok !== 'boolean' || typeof line.detail !== 'string') throw invalid();
    return { id: line.id, ok: line.ok, detail: line.detail };
  });
  if (typeof r.nodeFp !== 'string' || (r.nodeFp !== '' && !HEX128.test(r.nodeFp)) || typeof r.expiry !== 'string' || (r.expiry !== '' && !RAW.test(r.expiry))) throw invalid();
  if (r.ok !== checks.every(line => line.ok) || (r.ok && r.nodeFp === '')) throw invalid();
  return { ok: r.ok, checks, nodeFp: r.nodeFp, expiry: r.expiry === '' ? null : rawUnits(r.expiry, 'consent expiry') };
}
// The module's storageByOwner() answer, checked: tip, total, at most 256
// nodes (min(total, 256) of them), node fp strictly ascending, status 1..3.
export function parseStorageByOwner(result) {
  const invalid = () => new Error('The Nodus module returned an invalid storage node list.');
  if (!result || !Array.isArray(result.nodes) || result.nodes.length > 256) throw invalid();
  const tip = rawUnits(result.tip, 'block height'), total = rawUnits(result.total, 'storage node count');
  if (BigInt(result.nodes.length) !== (total < 256n ? total : 256n)) throw invalid();
  let last = '';
  const nodes = result.nodes.map(n => {
    if (!n || typeof n.fp !== 'string' || !HEX128.test(n.fp) || n.fp <= last || !Object.hasOwn(STORAGE_STATUS, n.status) || typeof n.member !== 'boolean' || !Number.isSafeInteger(n.failStreak) || n.failStreak < 0) throw invalid();
    last = n.fp;
    const status = STORAGE_STATUS[n.status];
    return {
      fp: n.fp, status, statusText: STORAGE_STATUS_TEXT[status], bond: rawUnits(n.bond, 'storage bond'), failStreak: n.failStreak,
      graceUntil: rawUnits(n.graceUntil, 'block height'), registered: rawUnits(n.registered, 'block height'), exit: rawUnits(n.exit, 'block height'),
      member: n.member, segments: rawUnits(n.segments, 'segment count')
    };
  });
  return { tip, total, nodes, hidden: total - BigInt(nodes.length) };
}
// This wallet's storage nodes (ONE node's committed tables, design G4).
export async function storageNodes({ client, from, signal } = {}) {
  hf6Ready(client, from);
  return parseStorageByOwner(await client.storageByOwner({ signal }));
}
// The module's read-back of an HF-6 envelope, checked for shape.
function decodeHf6(built, kind) {
  const d = built?.decoded, invalid = () => new Error('The Nodus module returned an invalid transaction.');
  if (!built || !(built.envelope instanceof Uint8Array) || built.envelope.length === 0 || typeof built.intentId !== 'string' || !HEX128.test(built.intentId) || !d) throw invalid();
  // UNSTAKE's call carries no node key (nodus-send-wasm.c nsw_hf6_core):
  // its nodeFp is ''; it names the witness by validatorId.
  const noConsent = kind === 'storageExit' || kind === 'unstake';
  if (d.op !== kind || typeof d.owner !== 'string' || !HEX128.test(d.owner) || typeof d.chainId !== 'string' || !HEX64.test(d.chainId)) throw invalid();
  if (kind === 'unstake' ? d.nodeFp !== '' : typeof d.nodeFp !== 'string' || !HEX128.test(d.nodeFp)) throw invalid();
  if (kind === 'unstake' ? typeof d.validatorId !== 'string' || !HEX128.test(d.validatorId) || d.validatorId === ZERO128 : d.validatorId !== '') throw invalid();
  if (noConsent ? d.consentExpiry !== '' : typeof d.consentExpiry !== 'string' || !RAW.test(d.consentExpiry)) throw invalid();
  if (!Array.isArray(d.inputs) || d.inputs.length < 1 || d.inputs.length > NODUS_MAX_INPUTS || new Set(d.inputs).size !== d.inputs.length || !d.inputs.every(input => typeof input === 'string' && HEX128.test(input))) throw invalid();
  return {
    envelope: built.envelope, intentId: built.intentId, owner: d.owner, nodeFp: d.nodeFp, validatorId: d.validatorId, chainId: d.chainId, inputs: [...d.inputs],
    bond: rawUnits(d.bond, 'bond'), commissionBps: rawUnits(d.commissionBps, 'commission'), fee: rawUnits(d.fee, 'network fee'),
    change: rawUnits(d.change, 'change amount'), expiryHeight: rawUnits(d.expiryHeight, 'expiry height'),
    consentExpiry: noConsent ? null : rawUnits(d.consentExpiry, 'consent expiry'), ...builtWire(built)
  };
}
// Builds and signs one HF-6 envelope for review, in the shape of
// prepareStake (cancel(), confirm(onBroadcast) usable once, refused after
// expiresAt). kind: HF6_KINDS. consent: the pasted text (not for
// storageExit / unstake). validatorId: the witness (unstake).
// nodeFp: the storage node (storageExit; it must be one of this wallet's
// storage nodes and storing — re-read here). bond: NODUS text (stake; at
// least the node's stakeMin — the storage bond is always exactly the node's
// storageBond; both read here with hf6Bonds). commissionBps: integer text
// (stake). locked: coins of pending NODUS transactions (lockedInputs) —
// never offered to the builder. A consent ending before the transaction's
// validity is refused (consentEndsBefore). Besides the stake shape it resolves
// `decoded` (what the module read back from the signed bytes: bond, fee,
// change, nodeFp, validatorId, consentExpiry, expiryHeight), `tip` (the
// coin listing's), `spendable` and `balanceAfter` (BigInt).
// unstake ("Stop being a witness", generation-4 UNSTAKE, op 3): the call is
// validator_id ‖ owner_fp (128 bytes; owner_fp = this wallet's fingerprint,
// written by the module's builder — Kurultay #18 "C2") and the chain
// refuses it unless owner_fp is the witness ROW's owner and the row is
// ACTIVE or ELIGIBLE (nodus_witness_rt_native.c rtn_unstake2_exec) — so the
// witness must be one of this wallet's own generation-4 witnesses in the node's list
// (ownerFp === this wallet) with status active or eligible
// (UNSTAKE_STATUSES), checked here before anything is built. Its decoded
// nodeFp is '' (the call carries no key) and no bond moves (fee only).
export const UNSTAKE_STATUSES = Object.freeze(['active', 'eligible']);
export async function prepareHf6({ client, from, kind, consent = '', validatorId = '', nodeFp = '', bond, commissionBps = '0', locked = new Set() } = {}) {
  hf6Ready(client, from);
  if (!HF6_KINDS.includes(kind)) throw new Error('Unknown witness or storage action.');
  const rules = parseHf6Rules(client.hf6Rules);
  // The bonds in force (chain parameters 19 / 21, BUGS W-20), read now from
  // the node — the build reads them again from its own fee answer and
  // refuses if they moved in between.
  const bonds = kind === 'stake' || kind === 'storageRegister' ? await hf6Bonds({ client, from }) : null;
  let amount = 0n, commission = 0n;
  if (kind === 'stake') {
    amount = nodusAmountUnits(bond);
    if (amount < bonds.stakeMin) throw new Error(`The witness bond is at least ${nodusText(bonds.stakeMin)}.`);
    if (typeof commissionBps !== 'string' || !/^(0|[1-9]\d{0,4})$/.test(commissionBps)) throw new Error('Enter a commission between 0% and 50%.');
    commission = BigInt(commissionBps);
    if (client.stakeable) {
      const { commissionMaxBps } = parseStakingRules(client.stakingRules);
      if (commission > commissionMaxBps) throw new Error(`The commission can be at most ${RATE(Number(commissionMaxBps))}.`);
    }
  } else if (kind === 'storageRegister') {
    amount = bonds.storageBond;
  }
  const byWitness = kind === 'unstake', noConsent = kind === 'storageExit' || kind === 'unstake';
  if (byWitness && (typeof validatorId !== 'string' || !HEX128.test(validatorId) || validatorId === ZERO128)) throw new Error('Choose one of your witnesses.');
  if (kind === 'storageExit' && (typeof nodeFp !== 'string' || !HEX128.test(nodeFp))) throw new Error('Choose one of your storage nodes.');
  if (!noConsent && (typeof consent !== 'string' || !consent.trim())) throw new Error('Paste the consent your node printed.');
  if (kind === 'unstake') {
    // the chain's own refusals, made here before anything is built
    if (!client.stakeable || typeof client.validators !== 'function') throw new Error('The witness list is not available in this wallet version.');
    const { validators } = parseValidators(await client.validators());
    const row = validators.find(v => v.hasV2 && v.validatorId === validatorId);
    if (!row || row.ownerFp !== from) throw new Error('This witness is not one of this wallet\'s witnesses. Nothing was sent.');
    if (!UNSTAKE_STATUSES.includes(row.status)) throw new Error(`This witness cannot stop now (${row.statusText}): only an active witness or one waiting for a seat can. Nothing was sent.`);
  }
  if (kind === 'storageExit') {
    // the chain's own refusals (rtn_storage_exit_exec: the node's owner must
    // be the caller, the node ACTIVE), made here from a fresh read of this
    // wallet's storage nodes before anything is built (BUGS W-21) — a node
    // not in the list (also one past the 256 the node lists) is refused
    const { nodes } = await storageNodes({ client, from });
    const row = nodes.find(n => n.fp === nodeFp);
    if (!row) throw new Error('This storage node is not in this wallet\'s list of storage nodes. Nothing was sent.');
    if (row.status !== 'active') throw new Error(`This storage node cannot leave now (${row.statusText}): only a node that is storing can. Nothing was sent.`);
  }
  const { spendable } = parseBalance(await client.balance());
  const listing = await client.list();
  const coins = parseCoins(listing);
  if (coins.length === 0 && spendable > 0n) throw new Error('Your coin list could not be read. Nothing was sent; try again later.');
  // HF-4: which rules the node runs; the HF-6 calls exist only from
  // hf6Rules.generation (design §3) — below it nothing is built.
  const ruleset = parseRulesetInfo(await client.rulesetInfo());
  if (ruleset.generation < rules.generation) throw new Error(HF6_NOT_YET_TEXT);
  const tip = parseTip(listing.tip), expiryHeight = expiryHeightFor(tip, ruleset);
  // The consent against the listing's tip — the one the module re-checks
  // it with (nodus-send-wasm.c nsw_hf6_build). Its node key and expiry must
  // be what the signed bytes carry.
  const check = noConsent ? null : checkConsent({ client, from, kind, text: consent, tip });
  if (check && !check.ok) throw new Error(`The consent did not pass its checks: ${check.checks.find(line => !line.ok).detail}`);
  // A consent that ends before this transaction's own validity: included
  // after the consent's block, the network refuses it (rtn_stake2_exec /
  // rtn_storage_register_exec check the consent expiry at the item's
  // height) — refused here, not left to a warning (BUGS W-21).
  if (check && (check.expiry === null || consentEndsBefore(check.expiry, expiryHeight))) throw new Error(CONSENT_ENDS_EARLY_TEXT);
  const candidates = coins.filter(coin => !locked.has(coin.nullifier));
  if (candidates.length === 0) throw new Error(locked.size ? 'Your coins are held by a pending transaction. Wait for it to be included or to expire.' : 'Insufficient NODUS balance.');
  const available = candidates.reduce((sum, coin) => sum + BigInt(coin.amount), 0n);
  if (amount > available) throw new Error(`This needs ${nodusText(amount)} plus the network fee; ${nodusText(available)} is free to spend (${nodusText(amount - available)} short). Nothing was sent.`);
  const d = decodeHf6(await client.hf6Build({
    op: kind, consent: noConsent ? '' : consent, validatorId: byWitness ? validatorId : '', nodeFp: kind === 'storageExit' ? nodeFp : '',
    amount: amount.toString(), commissionBps: commission.toString(), expiryHeight: expiryHeight.toString(), coins: candidates
  }), kind);
  // The signed envelope must be exactly what was requested, or nothing is shown.
  if (d.owner !== from || d.bond !== amount || d.commissionBps !== commission || d.expiryHeight !== expiryHeight || d.chainId !== client.chainId ||
      (byWitness && d.validatorId !== validatorId) || (kind === 'storageExit' && d.nodeFp !== nodeFp) || (kind === 'unstake' && d.nodeFp !== '') ||
      (check && (d.nodeFp !== check.nodeFp || d.consentExpiry !== check.expiry))) throw new Error('The signed transaction does not match your request. Nothing was sent.');
  const amounts = new Map(candidates.map(coin => [coin.nullifier, BigInt(coin.amount)]));
  if (!d.inputs.every(input => amounts.has(input))) throw new Error('The signed transaction uses coins it may not use. Nothing was sent.');
  const inSum = d.inputs.reduce((sum, input) => sum + amounts.get(input), 0n);
  if (inSum !== d.bond + d.fee + d.change) throw new Error('The signed transaction does not add up. Nothing was sent.');
  if (d.bond + d.fee > spendable) throw new Error(`This needs ${nodusText(d.bond + d.fee)}; ${nodusText(spendable)} is spendable (${nodusText(d.bond + d.fee - spendable)} short). Nothing was sent.`);
  const balanceAfter = spendable - d.bond - d.fee;
  const action = { stake: 'Become a witness', storageRegister: 'Become a storage node', storageExit: 'Leave storage', unstake: 'Stop being a witness' }[kind];
  const review = [['Network', 'Nodus testnet'], ['Action', action]];
  if (byWitness) review.push(['Witness', d.validatorId]);
  if (kind !== 'unstake') review.push(['Node key fingerprint', d.nodeFp]);
  if (d.bond > 0n) review.push(['Bond', nodusText(d.bond)]);
  if (kind === 'stake') review.push(['Commission', RATE(Number(d.commissionBps))]);
  review.push(['Owner (this wallet)', d.owner], ['Network fee', nodusText(d.fee)], ['Change back to you', nodusText(d.change)], ['Balance after', nodusText(balanceAfter)]);
  if (d.consentExpiry !== null) review.push(['Consent valid until block', d.consentExpiry.toString()]);
  review.push(['Valid until block', d.expiryHeight.toString()], ...expiryCapRows(tip, d.expiryHeight, ruleset), ['Chain ID', d.chainId], ['Fee note', 'The network fee may be charged even if the transaction fails.']);
  if (listing.truncated === true) review.push(['Coin list', 'Your coin list may be incomplete; only the coins listed are used.']);
  let used = false;
  const expiresAt = Date.now() + NODUS_REVIEW_MS;
  return {
    kind, chain: NODUS_ASSET.chain, from, to: d.owner, symbol: NODUS_ASSET.symbol, amount: formatUnits(d.bond, DECIMALS),
    endpoint: undefined, fee: nodusText(d.fee), expiresAt, review, intentId: d.intentId,
    decoded: { bond: d.bond, fee: d.fee, change: d.change, nodeFp: d.nodeFp, validatorId: d.validatorId, commissionBps: d.commissionBps, consentExpiry: d.consentExpiry, expiryHeight: d.expiryHeight, chainId: d.chainId },
    tip, spendable, balanceAfter,
    cancel() { used = true; },
    async confirm(onBroadcast) {
      if (used) throw new Error('This review is already closed.');
      used = true; // an ambiguous submission is never retried automatically
      if (Date.now() >= expiresAt) throw new Error('Review expired. Prepare it again.');
      // The record is durable before the envelope leaves the browser; its
      // inputs are held like a send's (lockedInputs) until it resolves.
      await onBroadcast({ hash: d.intentId, expiryHeight: d.expiryHeight.toString(), fromHeight: (tip + 1n).toString(), inputs: [...d.inputs], ...(d.wire ? { wire: d.wire } : {}) });
      await submitSigned(client, d.envelope, d.intentId, result => `The Nodus network did not accept this transaction. Its coins stay held until it expires.${refusalDetail(result)}`);
      return d.intentId;
    }
  };
}

// ── Chain-name registration (HF-4) ────────────────────────────────────────
// The module side is nodus-cli `name register` over the shared builder
// (crypto/nodus-send-wasm.c "CHAIN NAME REGISTRATION"); this side checks
// what crosses the boundary, shows availability and the price before
// anything is built, and builds the review from the module's own read-back
// of the signed envelope (G1). Rules (decision 2026-10-02-onchain-names.md;
// design docs/plans/2026-10-02-onchain-names-design.md rev 4 §2): first
// come wins, one name per ID, permanent (no expiry, no renewal); 3 to 36
// of a-z0-9, an all-hex name of 8+ characters is never a name; the price by
// length is the NODE's (dnac_fee_info) — never a number in this file; a
// refused registration never pays the price (design §2 "Refused
// registration"). The availability answers come from ONE node's committed
// state (decision item 9); the chain decides again when it runs it.
// The price parameters (dnac/include/dnac/dnac.h DNAC_CFG_NAME_PRICE_3P..6P).
export const NAME_PRICE_PARAMS = Object.freeze([10, 11, 12, 13]);
const NAME_PRICE_LENGTHS = Object.freeze(['3 characters', '4 characters', '5 characters', '6 or more characters']);
// The module's namePrices() answer, checked: four prices > 0 and at most 16
// scheduled changes of the four price parameters.
export function parseNamePrices(result) {
  const invalid = () => new Error('The Nodus module returned invalid name prices.');
  if (!result || !Array.isArray(result.prices) || result.prices.length !== 4 || !Array.isArray(result.scheduled) || result.scheduled.length > 16) throw invalid();
  const prices = result.prices.map(price => rawUnits(price, 'name price'));
  if (prices.some(price => price === 0n)) throw invalid();
  const scheduled = result.scheduled.map(row => {
    if (!row || !NAME_PRICE_PARAMS.includes(row.param)) throw invalid();
    const value = rawUnits(row.value, 'name price');
    if (value === 0n) throw invalid();
    return { param: row.param, value, effective: rawUnits(row.effective, 'block height') };
  });
  return { prices, scheduled };
}
// The price of `name` (a valid chain name) from parseNamePrices' list.
export function namePriceFor(prices, name) {
  if (!chainNameOk(name) || !Array.isArray(prices) || prices.length !== 4) throw new Error('Not a chain name: 3 to 36 letters a-z and digits.');
  return prices[name.length >= 6 ? 3 : name.length - 3];
}
// A one-line price list for the page: "3 characters: 1,000 NODUS · …".
export function namePriceList(prices) {
  return prices.map((price, i) => `${NAME_PRICE_LENGTHS[i]}: ${nodusText(price)}`).join(' · ');
}
function registerReady(client, from) {
  if (!client || client.state !== 'ready' || !client.nameable || !client.registrable) throw new Error('Registering a chain name is not available right now.');
  if (from !== client.fingerprint) throw new Error('Nodus address does not match the connected identity.');
}
// This wallet's own chain name: { found: false } or { found: true, name }.
export async function ownChainName({ client, from, signal } = {}) {
  if (!client || client.state !== 'ready' || !client.nameable) throw new Error('Chain names are not available right now.');
  if (from !== client.fingerprint) throw new Error('Nodus address does not match the connected identity.');
  return parseNameOf(await client.nameOf({ owner: from }, { signal }));
}
// What the page shows before anything is built, for what the person typed:
//   { status: 'has-name', ownName }        this ID already holds a name
//   { status: 'taken', name }              someone registered it first
//   { status: 'available', name, price, priceText, prices, scheduled }
// Throws for text that is not a chain name.
export async function nameQuote({ client, from, name: typed, signal } = {}) {
  registerReady(client, from);
  const name = chainName(typed);
  if (!name) throw new Error('A chain name is 3 to 36 letters a-z and digits (no spaces, dots or dashes). A name made only of 0-9 and a-f with 8 or more characters is not allowed, because it would look like an ID.');
  const own = parseNameOf(await client.nameOf({ owner: from }, { signal }));
  if (own.found) return { status: 'has-name', ownName: own.name };
  const found = parseNameLookup(await client.nameLookup({ name }, { signal }));
  if (found.found) return { status: 'taken', name };
  const { prices, scheduled } = parseNamePrices(await client.namePrices({ signal }));
  const price = namePriceFor(prices, name);
  return { status: 'available', name, price, priceText: nodusText(price), prices, scheduled };
}
// The module's read-back of a registration envelope, checked for shape.
function decodeName(built) {
  const d = built?.decoded, invalid = () => new Error('The Nodus module returned an invalid transaction.');
  if (!built || !(built.envelope instanceof Uint8Array) || built.envelope.length === 0 || typeof built.intentId !== 'string' || !HEX128.test(built.intentId) || !d) throw invalid();
  if (!chainNameOk(d.name) || typeof d.owner !== 'string' || !HEX128.test(d.owner) || typeof d.chainId !== 'string' || !HEX64.test(d.chainId)) throw invalid();
  if (!Array.isArray(d.inputs) || d.inputs.length < 1 || d.inputs.length > 13 || new Set(d.inputs).size !== d.inputs.length || !d.inputs.every(input => typeof input === 'string' && HEX128.test(input))) throw invalid();
  return {
    envelope: built.envelope, intentId: built.intentId, name: d.name, owner: d.owner, chainId: d.chainId, inputs: [...d.inputs],
    price: rawUnits(d.price, 'name price'), fee: rawUnits(d.fee, 'network fee'), change: rawUnits(d.change, 'change amount'),
    expiryHeight: rawUnits(d.expiryHeight, 'expiry height'), ...builtWire(built)
  };
}
// Builds and signs one registration of `name` for review, in the shape of
// prepareStake (cancel(), confirm(onBroadcast) usable once, refused after
// expiresAt). `locked`: coins of pending NODUS transactions (lockedInputs) —
// never offered to the builder.
export async function prepareName({ client, from, name: typed, locked = new Set() } = {}) {
  const quote = await nameQuote({ client, from, name: typed });
  if (quote.status === 'has-name') throw new Error(`This wallet already has the chain name "${quote.ownName}". Each Nodus ID can hold one name.`);
  if (quote.status === 'taken') throw new Error(`The name "${quote.name}" is already registered. Try another name.`);
  const { name } = quote;
  const { spendable } = parseBalance(await client.balance());
  const listing = await client.list();
  const coins = parseCoins(listing);
  if (coins.length === 0 && spendable > 0n) throw new Error('Your coin list could not be read. Nothing was sent; try again later.');
  // HF-4: which rules the node runs, then the expiry they allow.
  const ruleset = parseRulesetInfo(await client.rulesetInfo());
  if (ruleset.generation < 2n) throw new Error(ruleset.gen2Height > 0n ? `Chain names open at block ${ruleset.gen2Height}. Try again after that block.` : 'Chain names are not open on the Nodus network yet.');
  const tip = parseTip(listing.tip), expiryHeight = expiryHeightFor(tip, ruleset);
  const candidates = coins.filter(coin => !locked.has(coin.nullifier));
  if (candidates.length === 0) throw new Error(locked.size ? 'Your coins are held by a pending transaction. Wait for it to be included or to expire.' : 'Insufficient NODUS balance.');
  const d = decodeName(await client.nameBuild({ name, expiryHeight: expiryHeight.toString(), coins: candidates }));
  // The signed envelope must be exactly what was requested, or nothing is shown.
  if (d.name !== name || d.owner !== from || d.expiryHeight !== expiryHeight || d.chainId !== client.chainId) throw new Error('The signed transaction does not match your request. Nothing was sent.');
  if (d.price !== quote.price) throw new Error(`The price of this name changed while it was being prepared (now ${nodusText(d.price)}). Nothing was sent; prepare it again.`);
  const amounts = new Map(candidates.map(coin => [coin.nullifier, BigInt(coin.amount)]));
  if (!d.inputs.every(input => amounts.has(input))) throw new Error('The signed transaction uses coins it may not use. Nothing was sent.');
  const inSum = d.inputs.reduce((sum, input) => sum + amounts.get(input), 0n);
  if (inSum !== d.price + d.fee + d.change) throw new Error('The signed transaction does not add up. Nothing was sent.');
  const review = [
    ['Network', 'Nodus testnet'],
    ['Action', 'Register a chain name'],
    ['Name', d.name],
    ['Owner (your Nodus ID)', d.owner],
    ['Name check', 'Names can look alike (for example the digit 0 and the letter o). Check that this is exactly the name you want.'],
    ['Price', nodusText(d.price)],
    ['Network fee', nodusText(d.fee)],
    ['Total', nodusText(d.price + d.fee)],
    ['Change back to you', nodusText(d.change)],
    ['Rules', 'First come, first served: if someone registers this name before yours is included, yours is refused and the price is not charged. Each Nodus ID can hold one name. The name does not expire and needs no renewal.']
  ];
  const changing = quote.scheduled.filter(row => row.effective <= d.expiryHeight);
  if (changing.length) review.push(['Price change', `A name price change is scheduled at block ${changing.map(row => row.effective).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))[0]}. If it takes effect before this registration is included, the registration is refused and the price is not charged; prepare it again.`]);
  review.push(['Valid until block', d.expiryHeight.toString()], ...expiryCapRows(tip, d.expiryHeight, ruleset), ['Chain ID', d.chainId], ['Fee note', 'The network fee may be charged even if the transaction fails.']);
  if (listing.truncated === true) review.push(['Coin list', 'Your coin list may be incomplete; only the coins listed are used.']);
  let used = false;
  const expiresAt = Date.now() + NODUS_REVIEW_MS;
  return {
    kind: 'name', name: d.name, chain: NODUS_ASSET.chain, from, to: d.owner, symbol: NODUS_ASSET.symbol, amount: formatUnits(d.price, DECIMALS),
    endpoint: undefined, fee: nodusText(d.fee), expiresAt, review, intentId: d.intentId,
    cancel() { used = true; },
    async confirm(onBroadcast) {
      if (used) throw new Error('This review is already closed.');
      used = true; // an ambiguous submission is never retried automatically
      if (Date.now() >= expiresAt) throw new Error('Review expired. Prepare it again.');
      // The record is durable before the envelope leaves the browser; its
      // inputs are held like a send's (lockedInputs) until it resolves.
      await onBroadcast({ hash: d.intentId, expiryHeight: d.expiryHeight.toString(), fromHeight: (tip + 1n).toString(), inputs: [...d.inputs], ...(d.wire ? { wire: d.wire } : {}) });
      await submitSigned(client, d.envelope, d.intentId, result => `The Nodus network did not accept this registration. Its coins stay held until it expires.${refusalDetail(result)}`);
      return d.intentId;
    }
  };
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

// ── Testnet faucet: "Get testnet coins" (operator 2026-10-22: "Cüzdanın
// içinde"; docs/plans/2026-10-22-testnet-faucet-design.md §6 item 11; the HTTP
// API is the one of docs/plans/2026-10-22-mm-dex-build-plan.md, package C) ──
// The wallet sends its OWN personal address to the faucet service on the
// wallet site's own origin (EU-6 forwards /faucet/ to the faucet host; no
// separate faucet site) and shows what it answers. The result arrives as
// ordinary incoming coins. Vault names are not part of the first version
// (operator "İlk sürümde yok"): the address is always this wallet's own.
//   POST /faucet/claim  {"address":"<128 lowercase hex>"} ->
//     {"claim_id":"<hex>","state":"planned|signed|submitted|confirmed|expired|
//      unknown|refused|paused","kind":"full|start|none","message":"…"}
//   GET  /faucet/claim/<claim_id> -> the same shape
// Final states: confirmed, expired, refused, unknown, paused. Anything else is
// in progress: the claim is polled a BOUNDED number of times; a claim still not
// final after that is "pending — check again later", never "failed" (the
// faucet may well pay it afterwards; it keeps its own journal). Display only:
// nothing here decides a balance, a signature or an amount.
export const NODUS_TESTNET_CHAIN_ID = 'a48d1a785500a1cdecd739ecd53ef0e95b1dc4a7a300f49176a7fa25ae176114';
export const FAUCET_STATES = Object.freeze(['planned', 'signed', 'submitted', 'confirmed', 'expired', 'unknown', 'refused', 'paused']);
export const FAUCET_FINAL = Object.freeze(['confirmed', 'expired', 'refused', 'unknown', 'paused']);
export const FAUCET_KINDS = Object.freeze(['full', 'start', 'none']);
export const FAUCET_MAX_POLLS = 20;
export const FAUCET_POLL_MS = 3000;
export const FAUCET_PENDING_TEXT = 'Pending — check again later. The faucet has not finished this claim yet; your coins arrive as soon as it does.';
// The button is offered only while the connected module reports the TESTNET
// chain (the id the module itself read from the node, client.chainId), for the
// connected identity.
export function faucetAvailable(client, address) {
  return !!client && client.state === 'ready' && client.chainId === NODUS_TESTNET_CHAIN_ID && typeof address === 'string' && HEX128.test(address) && address === client.fingerprint;
}
// One faucet answer, checked: exactly the documented keys' shapes, nothing
// else is trusted. -> { claimId, state, kind, message }.
export function parseFaucetClaim(answer) {
  const invalid = () => new Error('The faucet answered in a form this wallet does not understand.');
  if (!answer || typeof answer !== 'object' || Array.isArray(answer)) throw invalid();
  const { claim_id: claimId, state, kind, message } = answer;
  if (typeof claimId !== 'string' || !/^[0-9a-f]{8,128}$/.test(claimId) || !FAUCET_STATES.includes(state) || !FAUCET_KINDS.includes(kind) || typeof message !== 'string' || message.length > 500) throw invalid();
  return { claimId, state, kind, message };
}
// Bounds of one faucet exchange (a request, its body, the whole claim). A
// stalled request or body, or a faucet that never finishes, ends as
// "pending — check again later" after these; nothing waits for ever.
export const FAUCET_REQUEST_MS = 10000;
export const FAUCET_TOTAL_MS = 90000;
export const FAUCET_MAX_BODY = 4096;
// The POST was sent but its answer did not arrive (or was not readable): the
// faucet may have received it and may still pay, so this is NOT a failure.
export const FAUCET_LOST_TEXT = 'Pending — check again later. This wallet did not receive the faucet’s answer, so it cannot tell whether the request arrived; if it did, your coins arrive as soon as the faucet finishes.';
// The body of one answer, read with a size limit BEFORE it is parsed: the
// declared length, then the bytes actually read (a stream is cancelled at the
// limit). A response without a stream falls back to its text, then to json().
async function faucetBody(response) {
  const declared = Number(response?.headers?.get?.('content-length'));
  if (Number.isFinite(declared) && declared > FAUCET_MAX_BODY) throw new Error('The faucet is not available right now.');
  if (response?.body && typeof response.body.getReader === 'function') {
    const reader = response.body.getReader(), chunks = [];
    let size = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > FAUCET_MAX_BODY) { try { await reader.cancel(); } catch { /* already closing */ } throw new Error('The faucet is not available right now.'); }
      chunks.push(value);
    }
    const bytes = new Uint8Array(size);
    let at = 0;
    for (const chunk of chunks) { bytes.set(chunk, at); at += chunk.byteLength; }
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  }
  if (typeof response?.text === 'function') {
    const text = await response.text();
    if (typeof text !== 'string' || new TextEncoder().encode(text).length > FAUCET_MAX_BODY) throw new Error('The faucet is not available right now.');
    return text;
  }
  return undefined;
}
async function faucetJson(response) {
  let answer;
  try {
    const text = await faucetBody(response);
    answer = text === undefined ? await response.json() : JSON.parse(text);
  } catch { throw new Error('The faucet is not available right now.'); }
  // an answer that ARRIVED in a shape this wallet does not understand
  // (`shape`) is told as such; a lost / unreadable one is "pending"
  try { return parseFaucetClaim(answer); } catch (error) { error.shape = true; throw error; }
}
// A wait of `ms` (through `sleep`, injectable) that ends early — resolving, never
// rejecting — as soon as `signal` aborts or `stopped()` turns true (checked
// every STOP_CHECK_MS: `stopped` has no event). The caller re-checks both.
const STOP_CHECK_MS = 100;
async function cancellableSleep(sleep, ms, signal, stopped) {
  if (signal?.aborted || stopped()) return;
  let wake, timer, onAbort;
  const woken = new Promise(resolve => { wake = resolve; });
  onAbort = () => wake();
  signal?.addEventListener('abort', onAbort, { once: true });
  timer = setInterval(() => { if (stopped()) wake(); }, STOP_CHECK_MS);
  try { await Promise.race([sleep(ms), woken]); }
  finally { clearInterval(timer); signal?.removeEventListener('abort', onAbort); }
}
// Asks the faucet for the open wallet's coins and follows the claim.
// `fetcher` / `sleep` / `now` exist for tests. `onState(claim)`: told of every
// answer read (a status line); `stopped()` / `signal`: the wallet is closed —
// every request in flight is aborted and the polling ends quietly. Every
// request carries its own deadline (`requestMs`, covering its body too), the
// whole claim `totalMs`; requests are same-origin only and a redirect is an
// error (mode 'same-origin', redirect 'error'). Resolves { state, kind,
// message, claimId } of the last answer, with state 'pending' (and a text that
// says so) when the poll bound or the total deadline ran out first, or when
// the POST's answer was lost (timeout, network fault, unreadable body);
// rejects before anything was sent, and when the first answer ARRIVED in a
// shape this wallet does not understand.
export async function claimTestnetCoins({ client, address, fetcher = (...args) => globalThis.fetch(...args), sleep = ms => new Promise(resolve => setTimeout(resolve, ms)), now = () => performance.now(), onState = () => {}, stopped = () => false, signal, requestMs = FAUCET_REQUEST_MS, totalMs = FAUCET_TOTAL_MS } = {}) {
  if (!faucetAvailable(client, address)) throw new Error('Testnet coins are available only on the Nodus testnet while the wallet is connected.');
  const deadline = now() + totalMs;
  // One exchange: request + body, under its own AbortController, which the
  // per-request timer, the total deadline and the caller's signal all abort.
  // The race also ends a fetcher that ignores its signal.
  const exchange = async (url, init) => {
    const left = deadline - now();
    if (left <= 0 || signal?.aborted) throw new Error('The faucet exchange ran out of time.');
    const controller = new AbortController();
    const abort = () => controller.abort();
    signal?.addEventListener('abort', abort, { once: true });
    const timer = setTimeout(abort, Math.min(requestMs, left));
    const aborted = new Promise((_, reject) => controller.signal.addEventListener('abort', () => reject(new Error('The faucet exchange was aborted.')), { once: true }));
    try {
      return await Promise.race([(async () => faucetJson(await fetcher(url, { ...init, cache: 'no-store', credentials: 'omit', mode: 'same-origin', redirect: 'error', signal: controller.signal })))(), aborted]);
    } finally { clearTimeout(timer); signal?.removeEventListener('abort', abort); controller.abort(); }
  };
  let claim;
  try { claim = await exchange('/faucet/claim', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ address }) }); }
  catch (error) {
    if (error?.shape === true) throw error;      // it answered, in a form we cannot read
    return { claimId: undefined, state: 'pending', kind: 'none', message: FAUCET_LOST_TEXT };
  }
  onState(claim);
  for (let poll = 0; !FAUCET_FINAL.includes(claim.state); poll++) {
    if (poll >= FAUCET_MAX_POLLS || deadline - now() <= 0 || stopped() || signal?.aborted) return { ...claim, state: 'pending', message: FAUCET_PENDING_TEXT };
    // The wait is never longer than the time left (the deadline), and ends at
    // once when the wallet closes (`signal` abort / `stopped()`).
    await cancellableSleep(sleep, Math.min(FAUCET_POLL_MS, deadline - now()), signal, stopped);
    if (stopped() || signal?.aborted) return { ...claim, state: 'pending', message: FAUCET_PENDING_TEXT };
    try {
      const next = await exchange(`/faucet/claim/${claim.claimId}`, { method: 'GET' });
      // the answer must be for THIS claim
      if (next.claimId === claim.claimId) { claim = next; onState(claim); }
    } catch { /* a poll that fails counts against the bound; the next one asks again */ }
  }
  return claim;
}
