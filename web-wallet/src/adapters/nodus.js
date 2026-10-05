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
import { NODUS_ASSET } from '../nodus/network.js';
import { chainName, chainNameOk, parseNameOf } from '../nodus/names.js';

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
// The module's rulesetInfo() answer (src/nodus/send-module.js), checked:
// { generation >= 1, tip, gen2Height (0 = no switch committed) } as BigInt.
export function parseRulesetInfo(result) {
  if (!result) throw new Error('The Nodus module returned invalid network rules.');
  const generation = rawUnits(result.generation, 'rule-set generation');
  if (generation === 0n) throw new Error('The Nodus module returned invalid network rules.');
  return { generation, tip: rawUnits(result.tip, 'block height'), gen2Height: rawUnits(result.gen2Height, 'block height') };
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
  const units = nodusAmountUnits(amount);
  // A chain name resolves to its owner first (one node, decision item 9).
  const { recipient, resolved } = await resolveNodusRecipient(client, to);
  const { spendable } = parseBalance(await client.balance());
  const listing = await client.list();
  const coins = parseCoins(listing);
  // A read error on the node answers "0 coins" (design §1.4); with a positive
  // spendable balance, an empty list is a read failure, not "insufficient".
  if (coins.length === 0 && spendable > 0n) throw new Error('Your coin list could not be read. Nothing was sent; try again later.');
  // HF-4: which rules the node runs, then the expiry they allow.
  const ruleset = parseRulesetInfo(await client.rulesetInfo());
  const tip = parseTip(listing.tip), expiryHeight = expiryHeightFor(tip, ruleset);
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
    ...(resolved ? nameReviewRows(resolved, { showOwner: false }) : []),
    ['To', decoded.recipient],
    resolved ? [...NAME_CHECK_ROW] : ['Address check', 'Nodus addresses have no checksum. Compare all 128 characters with your source.'],
    ['Amount', nodusText(decoded.amount)],
    ['Network fee', nodusText(decoded.fee)],
    ['Change back to you', nodusText(decoded.change)],
    ['Valid until block', decoded.expiryHeight.toString()],
    ...expiryCapRows(tip, decoded.expiryHeight, ruleset),
    ['Chain ID', decoded.chainId],
    ['Fee note', 'The network fee may be charged even if the transfer fails.']
  ];
  if (listing.truncated === true) review.push(['Coin list', 'Your coin list may be incomplete; the transfer uses only the coins listed.']);
  let used = false;
  return {
    to: decoded.recipient, recipientName: resolved?.name, amount: formatUnits(decoded.amount, DECIMALS), symbol: NODUS_ASSET.symbol, fee: nodusText(decoded.fee),
    // Review-dialog timeout only (UI). The envelope's own validity is its
    // expiry height, checked by the chain.
    expiresAt: Date.now() + NODUS_REVIEW_MS,
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
  const invalid = () => new Error('The Nodus module returned an invalid validator list.');
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
    return { fingerprint: v.fingerprint, selfStake: rawUnits(v.selfStake, 'validator stake'), delegated: rawUnits(v.delegated, 'validator stake'), commissionBps: v.commissionBps, status, statusText: STATUS_TEXT[status], acceptsDelegation: status === 'active' || status === 'eligible', delegators };
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
// the module needs the validator's key) and whether this wallet is itself a
// validator (its own fingerprint listed with any status but 'unstaked').
export async function stakingOverview({ client, from, signal } = {}) {
  stakeReady(client, from);
  const rules = parseStakingRules(client.stakingRules);
  const { truncated, validators } = parseValidators(await client.validators({ signal }));
  const delegations = parseDelegations(await client.delegations({ signal }));
  const byKey = new Map(validators.map(v => [v.fingerprint, v]));
  const own = byKey.get(from);
  return {
    rules, truncated, validators,
    delegations: delegations.map(row => ({ ...row, validatorInfo: byKey.get(row.validator), canUndelegate: byKey.has(row.validator) })),
    ownValidator: own && own.status !== 'unstaked' ? own : undefined,
    lockText: `${rules.undelegateLockEpochs} epochs (${rules.undelegateLockEpochs} × ${rules.epochLength} = ${rules.undelegateLockEpochs * rules.epochLength} blocks)`
  };
}
// The module's read-back of a staking envelope, checked for shape.
function decodeStake(built) {
  const d = built?.decoded, invalid = () => new Error('The Nodus module returned an invalid transaction.');
  if (!built || !(built.envelope instanceof Uint8Array) || built.envelope.length === 0 || typeof built.intentId !== 'string' || !HEX128.test(built.intentId) || !d) throw invalid();
  if (!['stake', 'delegate', 'undelegate'].includes(d.op) || typeof d.validator !== 'string' || !HEX128.test(d.validator) || typeof d.chainId !== 'string' || !HEX64.test(d.chainId)) throw invalid();
  if (!Array.isArray(d.inputs) || d.inputs.length < 1 || d.inputs.length > NODUS_MAX_INPUTS || new Set(d.inputs).size !== d.inputs.length || !d.inputs.every(input => typeof input === 'string' && HEX128.test(input))) throw invalid();
  return {
    envelope: built.envelope, intentId: built.intentId, op: d.op, validator: d.validator, chainId: d.chainId, inputs: [...d.inputs],
    amount: rawUnits(d.amount, 'transaction amount'), commissionBps: rawUnits(d.commissionBps, 'commission'), fee: rawUnits(d.fee, 'network fee'),
    change: rawUnits(d.change, 'change amount'), expiryHeight: rawUnits(d.expiryHeight, 'expiry height')
  };
}
// Builds and signs one staking envelope for review, in the shape of
// prepareClaim (cancel(), confirm(onBroadcast) usable once, refused after
// expiresAt). kind: 'delegate' | 'undelegate' | 'stake'. `validator`: 128
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
    if (view.ownValidator) throw new Error('This wallet is already a validator.');
    units = rules.selfStake;
    if (typeof commissionBps !== 'string' || !/^(0|[1-9]\d{0,4})$/.test(commissionBps)) throw new Error('Enter a commission between 0% and 50%.');
    commission = BigInt(commissionBps);
    if (commission > rules.commissionMaxBps) throw new Error(`The commission can be at most ${RATE(Number(rules.commissionMaxBps))}.`);
    target = from;
  } else {
    target = typeof validator === 'string' ? validator : '';
    if (!HEX128.test(target)) throw new Error('Choose a validator.');
    units = nodusAmountUnits(amount);
    if (units === 0n) throw new Error('Enter an amount above zero.');
    existing = view.delegations.find(row => row.validator === target);
    const info = view.validators.find(v => v.fingerprint === target);
    if (kind === 'delegate') {
      if (!info) throw new Error('This validator is not in the current validator list.');
      if (!info.acceptsDelegation) throw new Error(`This validator does not accept delegations now (${info.statusText}).`);
      if (!existing && units < rules.minDelegation) throw new Error(`A new delegation must be at least ${formatUnits(rules.minDelegation, DECIMALS)} NODUS.`);
      // The chain admits a NEW delegator only below the per-validator cap; a
      // top-up of an existing delegation is exempt (nodus_witness_rt_native.c
      // rtn_delegate_exec: `!dr->present && count >= cap` refuses). Checked
      // only when the node reported the count (null = unknown: the chain decides).
      if (!existing && info.delegators !== null && BigInt(info.delegators) >= rules.maxDelegators) throw new Error(`This validator already has the most delegators it can take (${info.delegators}/${rules.maxDelegators}). Choose another validator.`);
    } else {
      if (!existing) throw new Error('You have no delegation with this validator.');
      if (!info) throw new Error('This validator is not in the current validator list, so its delegation cannot be withdrawn from here.');
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
  const review = [['Network', 'Nodus testnet']];
  if (kind === 'delegate') {
    review.push(['Action', 'Delegate NODUS'], ['Validator', d.validator], ['Validator commission', info ? RATE(info.commissionBps) : '—'],
      ['Amount', nodusText(d.amount)], ['Network fee', nodusText(d.fee)], ['Change back to you', nodusText(d.change)],
      ['Note', `The delegated NODUS stays yours but is held with this validator and cannot be sent while delegated. To get it back you undelegate; it then returns to you locked for ${view.lockText} after the validator set changes.`]);
  } else if (kind === 'undelegate') {
    review.push(['Action', 'Undelegate NODUS'], ['Validator', d.validator], ['Amount returned to you', nodusText(d.amount)],
      ['Network fee', `${nodusText(d.fee)} (paid from your spendable NODUS)`], ['Change back to you', nodusText(d.change)],
      ['Lock', `The returned NODUS arrives as a separate coin at your address. It stays locked for ${view.lockText} after the validator set next changes; until then it cannot be sent or delegated again.`]);
  } else {
    review.push(['Action', 'Become a validator'], ['Bond', nodusText(d.amount)], ['Commission', RATE(Number(d.commissionBps))],
      ['Bond returns to', `${from} (your own address)`], ['Network fee', nodusText(d.fee)], ['Change back to you', nodusText(d.change)],
      ['Important', 'The bond stays locked while you are a validator. This wallet has no way to unstake it: there is no leave-the-validator-set action here. An active validator is expected to take part in producing blocks; one that does not is retired automatically.']);
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
      await onBroadcast({ hash: d.intentId, expiryHeight: d.expiryHeight.toString(), fromHeight: (tip + 1n).toString(), inputs: [...d.inputs] });
      const result = await client.submit({ envelope: d.envelope });
      if (!result || result.accepted !== true) throw new Error(`The Nodus network did not accept this transaction. Its coins stay held until it expires.${typeof result?.message === 'string' && result.message ? ` ${result.message}` : ''}`);
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
    expiryHeight: rawUnits(d.expiryHeight, 'expiry height')
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
      await onBroadcast({ hash: d.intentId, expiryHeight: d.expiryHeight.toString(), fromHeight: (tip + 1n).toString(), inputs: [...d.inputs] });
      const result = await client.submit({ envelope: d.envelope });
      if (!result || result.accepted !== true) throw new Error(`The Nodus network did not accept this registration. Its coins stay held until it expires.${typeof result?.message === 'string' && result.message ? ` ${result.message}` : ''}`);
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
