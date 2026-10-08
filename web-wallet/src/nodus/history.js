// NODUS account history (0.1.78) — the wallet's NODUS Activity from the
// node's address history, decision docs/plans/decisions/2026-10-01-node-
// address-history-index.md item 6 ("Cüzdan Activity (NODUS) geçmişi düğümden
// doldurur (başka cihazdan yapılanlar dahil)"), over the rev 2 RPC
// `dnac_addr_history` (wire: nodus/include/nodus/nodus.h beside
// nodus_client_dnac_addr_history; rows: nodus/src/witness/
// nodus_witness_addr_index.h). The send module reads one page of THIS
// wallet's own address (crypto/nodus-send-wasm.c nsw_addr_history); this file
// checks it (parseAddrHistory), turns each row into plain words
// (nodusHistoryRow) and decides which of this tab's own records the node's
// rows already show (localRowsToShow). Pure functions, no network, no DOM.
//
// What the index holds — and so what this page can say (read in
// nodus_witness_addr_index.c nodus_witness_addr_index_env and the header's
// ROW DERIVATION):
//   - ONE node's local index, NOT consensus: it starts at the node's
//     `from_height` (no backfill, operator "zamanla dolsun") and another node
//     may answer differently. Every text below says "one Nodus node".
//   - kinds: spend_out | spend_in | burn | token_create | claim | stake |
//     delegate | undelegate | unstake | validator_update | payout | release |
//     fee | name (HF-4) | evm_deposit (Nodus EVM) — the last two defined in
//     nodus_witness_addr_index.c, accepted by the client's decoder
//     nodus_client.c AHD_KINDS, which is compiled into src/nodus/send.wasm.
//     An unknown kind makes the client refuse the whole page
//     (nodus_dnac_addr_history_decode): the wallet then shows its own
//     records only — never an empty history.
//   - smart contracts: an EVM leg writes no row; a DEPOSIT writes an
//     "evm_deposit" row on the payer, amount = what it locks into the
//     smart-contract reserve (the fee rides on it); a contract call without
//     a value writes only the payer's "fee" row; a WITHDRAW / REDEEM writes
//     a "release" row on the recipient, carrying the item's wire id. A
//     deposit indexed by a node older than the evm_deposit row shows as
//     "Fee" only.
//   - "release" with NO wire id is a block-boundary row (i = 4294967295):
//     a stake or delegation released at graduation; WITH a wire id it is the
//     smart-contract release above. "payout" is always a boundary row.
//   - a NAME_REGISTER is a "name" row on its owner, amount = the price.
//   - a shared-vault (multisig) spend is written on the VAULT's address
//     (the payer is the first satisfied multisig address), so a member's
//     own history does not list it — only a "Received" row when the member
//     is a recipient, its counterparty being the vault's address.
//   - "fee" carries the envelope's fee on the payer's FIRST row of the
//     item; a row of kind "fee" (amount 0) when the payer has no other row.
//   - claims, payouts and releases have no sender (peer "").

export const NODUS_HISTORY_LIMIT = 50;           // rows per read: src/history.js HISTORY_LIMIT
export const NODUS_HISTORY_MAX_LIMIT = 100;      // nodus.h NODUS_DNAC_ADDR_HISTORY_MAX_LIMIT
export const BOUNDARY_POS = 4294967295n;         // nodus.h: "i" of a block-boundary row
export const NODUS_HISTORY_KINDS = Object.freeze(['spend_out', 'spend_in', 'burn', 'token_create', 'claim', 'stake', 'delegate', 'undelegate', 'unstake', 'validator_update', 'payout', 'release', 'fee', 'name', 'evm_deposit']);
const U64 = /^(0|[1-9]\d{0,19})$/, HEX128 = /^[0-9a-f]{128}$/, NATIVE = '0'.repeat(128);
const U64_MAX = 2n ** 64n - 1n, U32_MAX = 2n ** 32n - 1n;
const DECIMALS = 8;                               // src/nodus/network.js NODUS_ASSET.decimals

const invalid = () => new Error('The Nodus node returned an invalid account history.');
const u64 = (value, max = U64_MAX) => {
  if (typeof value !== 'string' || !U64.test(value)) throw invalid();
  const v = BigInt(value);
  if (v > max) throw invalid();
  return v;
};

// The module's page (send-module.js addrHistory) checked field by field:
// exactly the keys of nodus.h, (h, i, q) strictly descending, a known kind,
// token 128 hex, peer and wire 128 hex or "", a boundary row (i =
// 4294967295) without a wire id and a non-boundary row with one, "payout"
// only on a boundary row, at most `limit` rows. Anything else throws.
// -> { enabled, fromHeight: bigint, entries: [{ h, i, q, amount, fee, ts:
//    bigint, kind, token, peer, wire: string }] }
export function parseAddrHistory(page, { limit = NODUS_HISTORY_LIMIT } = {}) {
  if (!page || typeof page !== 'object' || Array.isArray(page) || Object.keys(page).sort().join() !== 'enabled,entries,from_height') throw invalid();
  if (typeof page.enabled !== 'boolean' || !Array.isArray(page.entries) || page.entries.length > limit || page.entries.length > NODUS_HISTORY_MAX_LIMIT) throw invalid();
  const fromHeight = u64(page.from_height);
  let previous = null;
  const entries = page.entries.map(e => {
    if (!e || typeof e !== 'object' || Array.isArray(e) || Object.keys(e).sort().join() !== 'amount,fee,h,i,kind,peer,q,token,ts,wire') throw invalid();
    const row = { h: u64(e.h), i: u64(e.i, U32_MAX), q: u64(e.q, U32_MAX), kind: e.kind, amount: u64(e.amount), token: e.token, fee: u64(e.fee), peer: e.peer, wire: e.wire, ts: u64(e.ts) };
    if (!NODUS_HISTORY_KINDS.includes(row.kind) || typeof row.token !== 'string' || !HEX128.test(row.token) ||
        typeof row.peer !== 'string' || !(row.peer === '' || HEX128.test(row.peer)) ||
        typeof row.wire !== 'string' || !(row.wire === '' || HEX128.test(row.wire))) throw invalid();
    const boundary = row.i === BOUNDARY_POS;
    if (boundary !== (row.wire === '') || (row.kind === 'payout' && !boundary)) throw invalid();
    if (previous && !(row.h < previous.h || (row.h === previous.h && (row.i < previous.i || (row.i === previous.i && row.q < previous.q))))) throw invalid();
    previous = row;
    return row;
  });
  return { enabled: page.enabled, fromHeight, entries };
}

// Raw units -> decimal text with the NODUS decimals: "1.0", "0.00019388"
// (the same form as ethers formatUnits, which the rest of the wallet shows).
export function nodusUnits(units) {
  const scale = 10n ** BigInt(DECIMALS);
  const fraction = (units % scale).toString().padStart(DECIMALS, '0').replace(/0+$/, '');
  return `${units / scale}.${fraction || '0'}`;
}
export const shortId = id => (id.length > 18 ? `${id.slice(0, 8)}…${id.slice(-6)}` : id);

// What each kind says: [title, sign of the amount, how the counterparty is
// introduced]. The sign only marks value leaving ('out') or arriving ('in')
// at this address; staking rows keep their NODUS (held, not paid away) and
// carry no sign.
const KIND_TEXT = Object.freeze({
  spend_out: ['Sent', 'out', 'to'],
  spend_in: ['Received', 'in', 'from'],
  burn: ['Burned', 'out', ''],
  token_create: ['Token created', 'in', 'created by'],
  claim: ['Claimed', 'in', ''],
  stake: ['Staked', '', ''],
  delegate: ['Delegated', '', 'to witness'],
  undelegate: ['Undelegated', '', 'from witness'],
  unstake: ['Unstaked', '', ''],
  validator_update: ['Witness update', '', ''],
  payout: ['Reward payout', 'in', ''],
  release: ['Stake released', 'in', ''],
  fee: ['Fee', 'out', ''],
  name: ['Chain name registered', 'out', ''],
  evm_deposit: ['Moved to smart contracts', 'out', '']
});
// A "release" carrying a wire id is the smart-contract release (EVM
// WITHDRAW / REDEEM), not a graduation release (see the top of this file).
const EVM_RELEASE = 'Moved back from smart contracts';

// One checked entry -> what the page shows. `names`: Map fingerprint ->
// chain name ('' = none) from the wallet's name lookups; a name is shown
// beside the short address, never instead of it.
// -> { key, kind, title, sign ('+' | '−' | ''), amount (text, '' when the
//    row moves nothing), detail (the line below), height, time (ms or null),
//    wire, dir ('in' | 'out' | '') }
export function nodusHistoryRow(entry, { names = new Map() } = {}) {
  const [baseTitle, dir, peerWord] = KIND_TEXT[entry.kind];
  const title = entry.kind === 'release' && entry.wire !== '' ? EVM_RELEASE : baseTitle;
  const native = entry.token === NATIVE;
  const units = entry.kind === 'fee' ? entry.fee : entry.amount;
  const amount = units === 0n ? ''
    : native ? `${nodusUnits(units)} NODUS`
    // No token registry in the wallet: the raw units and a short token id.
    : `${units} units of token ${shortId(entry.token)}`;
  const parts = [];
  if (entry.peer && peerWord) {
    const name = names.get(entry.peer);
    parts.push(`${peerWord} ${name ? `${name} (${shortId(entry.peer)})` : shortId(entry.peer)}`);
  }
  if (entry.kind === 'fee') parts.push('network fee');
  else if (entry.fee > 0n) parts.push(`fee ${nodusUnits(entry.fee)} NODUS`);
  if (entry.kind === 'stake') parts.push('bond held while you are a witness');
  const sign = amount === '' ? '' : dir === 'in' ? '+' : dir === 'out' ? '−' : '';
  const ms = entry.ts * 1000n;
  return {
    key: `${entry.h}:${entry.i}:${entry.q}`, kind: entry.kind, title, sign, amount, detail: parts.join(' · '),
    height: entry.h.toString(), time: entry.ts > 0n && ms <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(ms) : null,
    wire: entry.wire, dir
  };
}

// The line above the list. `page`: parseAddrHistory's answer or null;
// `error`: the read's failure message or ''; `reading`: a read is running;
// `readAt`: text of when the page was read.
export function nodusHistoryStatus({ page = null, error = '', reading = false, readAt = '', limit = NODUS_HISTORY_LIMIT } = {}) {
  if (reading) return 'Reading account history from one Nodus node…';
  if (error) return `Account history could not be read from the Nodus node: ${error} Your sends from this wallet are listed above.`;
  if (!page) return 'Account history has not been read yet.';
  if (page.fromHeight === 0n) return `This Nodus node keeps no account history${page.enabled ? ' yet' : ''}. Your sends from this wallet are listed above.`;
  const parts = [`Newest ${limit} entries as reported by one Nodus node${readAt ? `, read ${readAt}` : ''}.`];
  if (page.fromHeight > 1n) parts.push(`History from block ${page.fromHeight}: this node keeps nothing older.`);
  if (!page.enabled) parts.push('This node is not recording new entries right now, so the newest ones may be missing.');
  return parts.join(' ');
}

// Which of this tab's own NODUS records (src/activity.js recordActivity) the
// page does NOT already show — the node's row is shown instead of a record
// it lists. Two matches, each on what BOTH sides hold:
//   (a) the full-wire id: a record built in this tab keeps the signed
//       envelope's wire id (`wire`, src/adapters/nodus.js builtWire, never
//       saved) and the node's row carries the same id ("wire" = the
//       preflight wire_id). Any status: a send still 'pending' here that the
//       node already lists is shown once.
//   (b) the block height: a record the tracker CONFIRMED carries the block
//       its scan found it in (`block`, src/adapters/nodus.js
//       checkNodusActivity); every applied transaction of this wallet
//       writes at least one row on this address at that height (the fee on
//       the payer's first row, or a claim row — nodus_witness_addr_index.c),
//       so a row of the page AT that height stands for it. A reloaded record
//       (no `wire`) is matched this way once re-confirmed. When the page is
//       full, its oldest height may be cut inside, so only heights above it
//       count there.
// Every other record stays shown (pending, failed, expired, a record whose
// block the node does not list — e.g. below its from_height).
export function localRowsToShow(rows, page, { limit = NODUS_HISTORY_LIMIT } = {}) {
  if (!page) return rows;
  const wires = new Set(page.entries.map(e => e.wire).filter(Boolean));
  const heights = new Set(page.entries.map(e => e.h));
  const full = page.entries.length >= limit, oldest = page.entries.length ? page.entries[page.entries.length - 1].h : null;
  return rows.filter(row => {
    if (typeof row.wire === 'string' && HEX128.test(row.wire) && wires.has(row.wire)) return false;
    if (row.status === 'confirmed' && typeof row.block === 'string' && U64.test(row.block)) {
      const block = BigInt(row.block);
      if (heights.has(block) && (!full || block > oldest)) return false;
    }
    return true;
  });
}
