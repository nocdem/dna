// Shared vaults — the panel in the NODUS account area of the wallet and of
// Nodus Connect, and the vault cards in Messages.
//
// Governing records: docs/plans/decisions/2026-09-29-general-multisig.md
// (M-of-N address, at most 7 keys per address, validity tip + 90 blocks;
// the Foundation 2-of-3), docs/plans/decisions/2026-09-25-web-wallet-nodus-
// send-transport.md (the wallet builds with the SAME C code nodus-cli uses:
// every address, payment and approval here comes from the module, src/
// nodus/send-module.js "SHARED VAULTS"), operator 2026-10-03 ("Connect'te
// kasa oluştur — üyeler isimle, adresi Connect hesaplar; üyelere mesajla
// haber verilir, tek dokunuşla eklenir; Foundation kasası hazır gelir;
// insanlar kendi kasalarını açabilsin"; a vault is listed only for its
// members — watching one is the user's own choice).
//
// HOST-DRIVEN like Messages: registered as a wallet extension (src/
// wallet-extensions.js) by both pages; it uses the wallet's ONE NODUS
// client (its queue) and, on the Nodus Connect page, Messages' vaultHost
// (src/connect/ui/messages.js) to tell members and to keep vaults with the
// saved wallet. On the wallet page (no Messages) vaults live for the
// session only, and proposing / approving says to use Nodus Connect.
//
// WHAT A MEMBER SEES IS READ BACK: a payment request is shown only from the
// module's read-back of its bytes (recipient, amount, fee, change, last
// valid block) — never from anyone's words; there are none in the message.
// Rendering: every text through textContent; names from Messages or the
// chain; no innerHTML.
import { FOUNDATION_VAULT } from './foundation.js';
import {
  VAULT_MAX_MEMBERS, VAULT_UNSUPPORTED, encodeShare, encodeRequest, encodeApproval, decodeVaultMessage, vaultCodeShape, vaultLabel,
  makeVaultRecord, checkVaultRecord, recordForStorage, applyCoins, collectVaultItems,
  requestState, blocksLeft, listedFor
} from './core.js';
import { amountUnits, formatUnits } from '../core.js';
import { chainName, parseNameOf } from '../nodus/names.js';
import { NODUS_ASSET } from '../nodus/network.js';
import { nodusHistoryRow, NODUS_HISTORY_LIMIT } from '../nodus/history.js';
// The session log (src/session-log.js, memory only, scrubbed).
import { sessionLog } from '../session-log.js';

const HEX128 = /^[0-9a-f]{128}$/;
// Reading a vault (0.1.82): Open / Refresh asks the node three things, each
// ONE module call (one slot of the wallet's one NODUS queue, src/nodus/
// client.js, so the connection check gets its turn between them): the
// balance (dnac_balance, public), the coins (vaultCoins) and the newest
// history page (vaultHistory) — the last two the node's MEMBER query
// (design docs/plans/2026-09-29-general-multisig-design.md §8.6 rev 2). No
// block is read; a node without the member query gets the plain "not
// updated yet" text and nothing else is tried (Kurultay #15: no fallback).

let client, ownFp, host = null, root, panel;
let generation = 0, busy = false, current = null, view = 'list';
const vaults = new Map();                // address -> record (core.js)
const balances = new Map();              // address -> { total, spendable }
// address -> what the last Open / Refresh read besides the balance:
// { truncated (the node has more coins than the page holds), history
// (parseAddrHistory's page or null), unsupported (the node has no member
// query) }. Session memory only; the coins themselves are in the record.
const reads = new Map();
const names = new Map();                 // ID -> chain name confirmed by nameOf ('' none)
const entered = new Map();               // ID -> the chain name this user typed (forward lookup only)
// Keyed by (vault address, digest) — rkey: a digest is only meaningful for
// the vault it was reviewed under (F1).
const reviews = new Map();               // rkey -> module read-back
// rkey -> the module's own text for the last review it REFUSED (0.1.85):
// shown on that request's card, as it is, never in the panel's status line
// (the user may have scrolled away from it). A later review that passes
// removes it.
const refusals = new Map();
const finishedOpen = new Set();          // vault addresses whose "Finished requests" the user opened
const ownApprovals = new Map();          // rkey -> signature text (this session)
const sent = new Map();                  // rkey -> { intentId, wireId, at } submitted here
const rkey = (address, digest) => `${address}|${digest}`;
const shareStates = new Map();           // vault code -> { state, info?, error? }
let status = '', draft = null, createInfo = null, foundationChecked = -1;
let loggedStatus = '';                    // the status line last sent to the session log (render)

const $ = id => document.getElementById(id);
function el(tag, { className, text } = {}, ...children) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  for (const child of children) if (child) node.append(child);
  return node;
}
// The button pressed for the action now running ({ index among the panel's
// buttons, label }): while `busy`, render() shows it as "Preparing…" (the
// panel is drawn again during an action, so the pressed node itself may be
// gone). Every button is disabled while busy, as before.
let pressed = null;
function btn(label, onClick, className = 'secondary small') {
  const node = el('button', { className, text: label });
  node.type = 'button';
  node.onclick = event => {
    pressed = root?.contains(node) ? { index: [...root.querySelectorAll('button')].indexOf(node), label } : null;
    return onClick(event);
  };
  return node;
}
const nodus = units => `${formatUnits(BigInt(units), NODUS_ASSET.decimals)} NODUS`;
const shortId = fp => `ID ${fp.slice(0, 8)}…${fp.slice(-4)}`;
// F5: a name is shown beside an ID only when the reverse lookup (nameOf,
// `names`) confirmed it — or Messages' own name for it, which is that same
// confirmed chain name or the short ID. A name only typed by this user
// (`entered`, from a forward lookup) is labelled unconfirmed.
function who(fp) {
  if (fp === ownFp) return 'you';
  const chain = names.get(fp);
  if (chain) return `${chain} · ${shortId(fp)}`;
  const named = host?.name(fp);
  if (named && named !== shortId(fp)) return named;
  const typed = entered.get(fp);
  return typed ? `${shortId(fp)} (entered as “${typed}”, name not confirmed)` : shortId(fp);
}
// F4: only the preset is called by its name alone; a name someone else
// chose is shown with who shared it.
const labelOf = record => {
  if (record.foundation) return FOUNDATION_VAULT.label;
  const name = record.label || `Shared vault ${record.address.slice(0, 8)}`;
  return record.from && record.from !== ownFp ? `${name} (shared by ${who(record.from)})` : name;
};
const messagesOpen = () => !!host && host.isOpen();

// ── lifecycle (wallet extension events) ─────────────────────────────────

function reset() {
  generation++;
  client = undefined; ownFp = undefined; busy = false; current = null; view = 'list';
  for (const map of [vaults, balances, reads, names, entered, reviews, refusals, finishedOpen, ownApprovals, sent, shareStates]) map.clear();
  status = ''; draft = null; createInfo = null;
  render();
}

async function start(detail) {
  reset();
  const c = detail?.client;
  if (!c || !c.vaultable) return;
  const gen = generation;
  client = c; ownFp = c.fingerprint;
  await loadVaults(gen);
}

// The listed vaults: the kept ones (Messages, saved wallet), the Foundation
// preset when this wallet is one of its members, and those of this
// session.
async function loadVaults(gen) {
  if (gen !== generation || !client || client.state !== 'ready') return;
  for (const kept of messagesOpen() ? host.vaults() : []) {
    if (vaults.has(kept.address)) continue;
    try {
      // a record kept by 0.1.80 / 0.1.81 (block-reading cursor, events, the
      // Foundation's `genesis` flag) loads as it is (core.js "RECORD
      // COMPATIBILITY"); its coins are replaced at the next Open
      const record = checkVaultRecord(kept.value);
      if (record.address !== kept.address || !listedFor(record, ownFp)) continue;
      // the address and members are derived again from the kept code by the
      // module; a record whose stored fields disagree is not listed
      const info = await client.vaultOpen({ descriptor: record.code });
      if (gen !== generation) return;
      if (info.address !== record.address || info.m !== record.m || info.n !== record.n ||
          info.members.length !== record.members.length || info.members.some((fp, i) => fp !== record.members[i])) continue;
      vaults.set(record.address, record);
    } catch { /* a damaged record is not listed; it can be added again from its message */ }
  }
  if (!vaults.has(FOUNDATION_VAULT.address) && foundationChecked !== gen) {
    foundationChecked = gen;
    try {
      const info = await client.vaultOpen({ descriptor: FOUNDATION_VAULT.descriptor });
      if (gen !== generation) return;
      // the module's own derivation must give the documented address
      if (info.address === FOUNDATION_VAULT.address && info.isMember) {
        // its coins (genesis outputs included) come from the node at Open
        await keep(makeVaultRecord({ info, label: FOUNDATION_VAULT.label, created: FOUNDATION_VAULT.created, foundation: true }));
      }
    } catch { /* not listed */ }
  }
  render();
  for (const record of vaults.values()) await nameMembers(record, gen);
}

async function nameMembers(record, gen) {
  for (const fp of record.members) {
    if (names.has(fp) || gen !== generation || !client?.nameable) continue;
    try {
      const r = parseNameOf(await client.nameOf({ owner: fp }));
      if (gen !== generation) return;
      names.set(fp, r.found ? r.name : '');
    } catch { names.set(fp, ''); }
  }
  if (gen === generation) render();
}

async function keep(record) {
  vaults.set(record.address, record);
  if (messagesOpen()) {
    try { await host.keepVault(record.address, recordForStorage(record)); }
    catch { status = 'This vault could not be saved on this device; it stays listed until you lock.'; }
  }
}

// ── reading a vault ──────────────────────────────────────────────────────

// The record as it is now: an Open / Refresh may have replaced its coins
// since a button was drawn.
const latest = record => vaults.get(record.address) ?? record;

// Open / Refresh: the balance first (drawn at once), then the coins, then
// the newest history page — one module call each, while `busy` (an action
// never builds on coins that are being replaced). A watched vault (this
// wallet is not a member) gets the balance only: the node answers its
// coins and history to members alone. The redraws keep what was typed in
// the payment form (keepTyped).
// reviewRequests (Open, 0.1.85): once the coins were read in THIS call,
// the vault's unreviewed payment requests are read too (reviewUnread) —
// never against coins that were not read (a watched vault, a node without
// the member query, a failed coin read): the module would refuse them.
async function refresh(address, { reviewRequests = false } = {}) {
  const record = vaults.get(address);
  if (!record || busy || !client) return;
  const gen = generation;
  busy = true; status = 'Reading the vault balance…'; render({ keepTyped: true });
  const problems = [];
  let coinsRead = false;
  try {
    const balance = await client.vaultBalance({ descriptor: record.code });
    if (gen !== generation) return;
    balances.set(address, balance);
    if (record.watch) { status = ''; return; }
    status = 'Reading the vault coins…'; render({ keepTyped: true });
    const read = { truncated: false, history: null, unsupported: false };
    try {
      const before = vaults.get(address);
      const answer = await client.vaultCoins({ descriptor: record.code });
      if (gen !== generation) return;
      // removed (or added again) while the read ran: nothing is kept
      if (!before || vaults.get(address) !== before) { status = ''; return; }
      const applied = applyCoins(before, answer);
      read.truncated = applied.truncated;
      await keep(applied.record);
      if (gen !== generation) return;
      coinsRead = true;
    } catch (error) {
      if (gen !== generation) return;
      if (error?.code === VAULT_UNSUPPORTED) {
        // no fallback: the page says so and reads nothing else
        read.unsupported = true;
        reads.set(address, read);
        status = '';
        sessionLog.log('vault', 'The Nodus node does not have the vault member query yet.', { error: true });
        return;
      }
      problems.push(error.message || 'The vault coins could not be read.');
    }
    status = 'Reading the vault history…'; render({ keepTyped: true });
    try {
      read.history = await client.vaultHistory({ descriptor: record.code, limit: NODUS_HISTORY_LIMIT });
      if (gen !== generation) return;
    } catch (error) {
      if (gen !== generation) return;
      problems.push(error.message || 'The vault history could not be read.');
    }
    reads.set(address, read);
    status = problems.join(' ');
  } catch (error) {
    if (gen === generation) status = error.message || 'The vault could not be read right now.';
  } finally {
    if (gen === generation) {
      busy = false; render({ keepTyped: true });
      if (reviewRequests && coinsRead && view === 'vault' && current === address) void reviewUnread(address, gen);
    }
  }
}

// Reading the requests on Open (0.1.85): every payment request of the vault
// with no review yet (and no refusal) is reviewed, newest first, ONE module
// call at a time through review() — `busy` is held for that one call only,
// and the event loop gets a turn between calls so a button can be pressed.
// It stops when the vault leaves the screen, the session changes
// (`generation`) or another action holds `busy`; at most
// VAULT_AUTO_REVIEWS per Open — the rest keep their "Review" button.
const VAULT_AUTO_REVIEWS = 16;
async function reviewUnread(address, gen) {
  const record = vaults.get(address);
  if (!record || record.watch) return;
  const unread = [...itemsFor(record).requests]
    .filter(([digest]) => !reviews.has(rkey(address, digest)) && !refusals.has(rkey(address, digest)))
    .sort((a, b) => b[1].at - a[1].at);
  if (unread.length > VAULT_AUTO_REVIEWS) sessionLog.log('vault', `${unread.length - VAULT_AUTO_REVIEWS} more payment request(s) were left to review by hand.`);
  for (const [digest, item] of unread.slice(0, VAULT_AUTO_REVIEWS)) {
    if (gen !== generation || view !== 'vault' || current !== address || busy || !client || !vaults.has(address)) return;
    const key = rkey(address, digest);
    if (reviews.has(key) || refusals.has(key)) continue;
    await review(latest(record), item.request);
    await new Promise(resolve => setTimeout(resolve, 0));
  }
}

// ── create ───────────────────────────────────────────────────────────────

async function resolveMember(text) {
  const value = text.replace(/\s+/g, '').toLowerCase();
  if (HEX128.test(value)) return value;
  const name = chainName(text);
  if (!name) throw new Error(`"${text.trim()}" is neither a chain name nor an ID.`);
  if (!client.nameable) throw new Error('Chain names cannot be looked up right now.');
  const r = await client.nameLookup({ name });
  if (!r?.found || !HEX128.test(r.owner ?? '')) throw new Error(`No one has registered the chain name "${name}".`);
  entered.set(r.owner, name);
  return r.owner;
}

async function checkMembers(form) {
  if (busy || !client) return;
  const gen = generation;
  busy = true; createInfo = null; status = 'Looking up the members…'; render();
  try {
    const typed = form.members.split('\n').map(s => s.trim()).filter(Boolean);
    const ids = [];
    for (const text of typed) { const fp = await resolveMember(text); if (gen !== generation) return; if (fp !== ownFp && !ids.includes(fp)) ids.push(fp); }
    for (const fp of form.contacts) if (fp !== ownFp && !ids.includes(fp)) ids.push(fp);
    if (ids.length + 1 > VAULT_MAX_MEMBERS) throw new Error(`A vault can have at most ${VAULT_MAX_MEMBERS} members, you included.`);
    if (ids.length < 1) throw new Error('Add at least one other member.');
    const m = Number(form.m);
    if (!Number.isInteger(m) || m < 1 || m > ids.length + 1) throw new Error('Choose how many members must approve a payment.');
    const label = vaultLabel(form.label);
    status = 'Reading the members’ accounts…'; render();
    const info = await client.vaultCreate({ members: ids, includeSelf: true, m });
    if (gen !== generation) return;
    createInfo = { info, label };
    // confirm each member's name by the reverse lookup before it is shown
    await nameMembers({ members: info.members }, gen);
    if (gen !== generation) return;
    status = '';
  } catch (error) {
    if (gen === generation) status = error.message || 'The vault could not be prepared.';
  } finally {
    if (gen === generation) { busy = false; render(); }
  }
}

async function createVault() {
  if (!createInfo || busy || !client) return;
  const gen = generation;
  busy = true; render();
  try {
    const ri = await client.rulesetInfo();
    if (gen !== generation) return;
    // the block it was created in (kept as the record's `created`, and sent
    // in the share message)
    const created = ri?.tip && /^[1-9]\d*$/.test(ri.tip) ? ri.tip : '1';
    const record = makeVaultRecord({ info: createInfo.info, label: createInfo.label, created });
    await keep(record);
    createInfo = null; draft = null; current = record.address; view = 'vault';
    status = messagesOpen() ? 'Vault created. Tell the members with “Share with members” so they can add it.' : 'Vault created for this session. Open Nodus Connect to tell the members and keep it.';
  } catch (error) {
    if (gen === generation) status = error.message || 'The vault could not be created.';
  } finally {
    if (gen === generation) { busy = false; render(); }
  }
}

// ── share / add ──────────────────────────────────────────────────────────

async function shareVault(record) {
  if (!messagesOpen() || busy) return;
  busy = true; render();
  const text = encodeShare({ code: record.code, label: record.label, created: record.created });
  const results = [];
  for (const fp of record.members) {
    if (fp === ownFp) continue;
    try { await host.send(fp, text); results.push(`${who(fp)}: sent`); }
    catch (error) { results.push(`${who(fp)}: ${error.message}`); }
  }
  status = results.join(' · ') || 'There is no other member to tell.';
  busy = false; render();
}

// A share message's "Add vault": first the module derives the address and
// the members from the code (shown), then a second tap adds it.
async function checkShare(item) {
  if (!client || shareStates.get(item.code)?.state === 'checking') return;
  shareStates.set(item.code, { state: 'checking' });
  host?.setPayloadView(payloadView);
  try {
    const info = await client.vaultOpen({ descriptor: item.code });
    if (!info.members.includes(item.from)) shareStates.set(item.code, { state: 'error', error: 'This vault was shared by someone who is not one of its members, so it is not added.' });
    else if (!info.isMember) shareStates.set(item.code, { state: 'error', error: 'You are not a member of this vault, so it is not added. You can still watch it from the Shared vaults panel.' });
    else shareStates.set(item.code, { state: 'confirm', info, item });
  } catch (error) { shareStates.set(item.code, { state: 'error', error: error.message || 'This vault could not be read.' }); }
  host?.setPayloadView(payloadView);
}

async function addShared(code) {
  const s = shareStates.get(code);
  if (!s || s.state !== 'confirm') return;
  // the card shows "Adding the vault…" instead of its button until this ends
  shareStates.set(code, { ...s, state: 'adding' });
  host?.setPayloadView(payloadView);
  try {
    // F6: the block a share says the vault was created at is never kept
    // past the node's tip
    const ri = await client.rulesetInfo();
    const tip = ri?.tip && /^[1-9]\d{0,19}$/.test(ri.tip) ? BigInt(ri.tip) : null;
    if (tip === null) throw new Error('The current Nodus block height is unknown. Try again in a minute.');
    const created = BigInt(s.item.created) > tip ? tip.toString() : s.item.created;
    const record = makeVaultRecord({ info: s.info, label: s.item.label, created, from: s.item.from });
    await keep(record);
    shareStates.set(code, { state: 'added' });
    await nameMembers(record, generation);
  } catch (error) { shareStates.set(code, { state: 'error', error: error.message || 'The vault could not be added.' }); }
  host?.setPayloadView(payloadView);
  render();
}

async function watchVault(form) {
  if (busy || !client) return;
  const gen = generation;
  busy = true; render();
  try {
    const code = form.code.replace(/\s+/g, '').toLowerCase();
    if (!vaultCodeShape(code)) throw new Error('This is not a vault code.');
    const info = await client.vaultOpen({ descriptor: code });
    if (gen !== generation) return;
    // `created` unknown for a code pasted by hand: block 1 (nothing reads
    // blocks from it since 0.1.82; a share message from here carries it)
    const record = makeVaultRecord({ info, label: form.label, created: '1', watch: !info.isMember });
    await keep(record);
    current = record.address; view = 'vault'; status = info.isMember ? 'Vault added.' : 'Vault added to watch. You cannot approve its payments.';
    await nameMembers(record, gen);
  } catch (error) {
    if (gen === generation) status = error.message || 'The vault could not be added.';
  } finally {
    if (gen === generation) { busy = false; render(); }
  }
}

async function removeVault(record) {
  vaults.delete(record.address);
  // its last read goes with it: a vault added again starts with no history
  reads.delete(record.address);
  if (messagesOpen()) { try { await host.dropVault(record.address); } catch { /* listed again after the next unlock */ } }
  current = null; view = 'list'; status = 'The vault was removed from this list. Its coins are not affected.';
  render();
}

// ── propose / review / approve / send ───────────────────────────────────

// A request's state (core.js requestState) from what this session holds for
// its vault: the record's coins (the node's last answer), whether that
// answer was cut short, the history page, and the wire id this wallet sent
// it under (if it did).
function stateOf(record, key, review, accepted) {
  const read = reads.get(record.address);
  return requestState({ review, accepted, record: latest(record), truncated: !!read?.truncated, wireId: sent.get(key)?.wireId ?? '', history: read?.history ?? null });
}

// Coins already used by a request of this session that is neither paid nor
// spent nor expired are not offered to a new one.
function freeCoins(record) {
  const held = new Set();
  for (const [key, review] of reviews) {
    if (review.vault !== record.address || review.expired) continue;
    const state = stateOf(record, key, review, 0);
    if (state === 'paid' || state === 'spent') continue;
    if (sent.has(key) || ownApprovals.has(key)) for (const id of review.inputs) held.add(id);
  }
  return record.coins.filter(c => !held.has(c.id));
}

async function prepareRequest(record, form) {
  if (busy || !client) return;
  const gen = generation;
  busy = true; draft = null; status = 'Preparing the payment…'; render();
  try {
    const typed = form.to.trim();
    const to = HEX128.test(typed.toLowerCase()) ? typed.toLowerCase() : await resolveMember(typed);
    const amount = amountUnits(form.amount.trim(), NODUS_ASSET.decimals).toString();
    const built = await client.vaultPropose({ descriptor: record.code, coins: freeCoins(latest(record)), to, amount });
    if (gen !== generation) return;
    reviews.set(rkey(record.address, built.request.digest), built.review);
    draft = { address: record.address, request: built.request, review: built.review, to };
    status = '';
  } catch (error) {
    if (gen === generation) status = error.message || 'The payment could not be prepared.';
  } finally {
    if (gen === generation) { busy = false; render(); }
  }
}

async function sendToMembers(record, texts) {
  const out = [];
  for (const fp of record.members) {
    if (fp === ownFp) continue;
    try { for (const text of texts) await host.send(fp, text); out.push(`${who(fp)}: sent`); }
    catch (error) { out.push(`${who(fp)}: ${error.message}`); }
  }
  return out.join(' · ');
}

// Approve a request this wallet reviewed (its own draft, or one received),
// and tell the other members: the request (for a new one) and the approval.
async function approve(record, request, { isNew }) {
  if (busy || !client) return;
  const gen = generation;
  busy = true; status = 'Approving…'; render();
  try {
    const { signature } = await client.vaultApprove({ descriptor: record.code, coins: latest(record).coins, request, digest: request.digest });
    if (gen !== generation) return;
    ownApprovals.set(rkey(record.address, request.digest), signature);
    // the count shown is the module's verified one, own approval included
    const review = await client.vaultReview({ descriptor: record.code, coins: latest(record).coins, request, approvals: approvalsFor(record.address, request.digest, itemsFor(record)) });
    if (gen !== generation) return;
    reviews.set(rkey(record.address, request.digest), review);
    const texts = [];
    if (isNew) texts.push(encodeRequest({ vault: record.address, request }));
    texts.push(encodeApproval({ vault: record.address, digest: request.digest, signature }));
    status = messagesOpen() ? `Approved. ${await sendToMembers(record, texts)}` : 'Approved for this session only: open Nodus Connect to send approvals to the members.';
    if (isNew) draft = null;
  } catch (error) {
    if (gen === generation) status = error.message || 'The payment could not be approved.';
  } finally {
    if (gen === generation) { busy = false; render(); }
  }
}

// Review / Check again, and each step of reviewUnread. A refusal is kept
// for the request's own card (`refusals`, the module's text as it is) and
// its earlier read-back is dropped: only the module's latest word about a
// request is shown or acted on (F1). The status line carries the progress
// only. Redraws keep what was typed in the payment form (the Open pass runs
// while the user may type).
async function review(record, request) {
  if (busy || !client) return;
  const gen = generation;
  const key = rkey(record.address, request.digest);
  busy = true; status = 'Reading the payment request…'; render({ keepTyped: true });
  try {
    const approvals = approvalsFor(record.address, request.digest, itemsFor(record));
    const answer = await client.vaultReview({ descriptor: record.code, coins: latest(record).coins, request, approvals });
    if (gen !== generation) return;
    reviews.set(key, answer);
    refusals.delete(key);
    status = '';
  } catch (error) {
    if (gen !== generation) return;
    const text = error?.message || 'This payment request could not be read.';
    reviews.delete(key);
    refusals.set(key, text);
    status = '';
    sessionLog.log('vault', `Payment request not valid: ${text}`, { error: true });
  } finally {
    if (gen === generation) { busy = false; render({ keepTyped: true }); }
  }
}

// The approval CANDIDATES for a request — the messages' ones (members only,
// core.js collectVaultItems) and this session's own — each with the ID it
// came from. The module verifies them (F2); only its verified count is
// shown or used.
function approvalsFor(address, digest, items) {
  const own = ownApprovals.get(rkey(address, digest));
  return [...(own ? [{ text: own, sender: ownFp }] : []), ...(items.approvals.get(digest) || [])];
}

function itemsFor(record) {
  return collectVaultItems(messagesOpen() ? host.messages() : [], record.address, record.members, ownFp);
}

async function sendPayment(record, request, items) {
  if (busy || !client) return;
  const gen = generation;
  busy = true; status = 'Sending the payment…'; render();
  try {
    const result = await client.vaultSubmit({ descriptor: record.code, coins: latest(record).coins, request, digest: request.digest, approvals: approvalsFor(record.address, request.digest, items) });
    if (gen !== generation) return;
    reviews.set(rkey(record.address, request.digest), result.review);
    if (result.accepted) {
      sent.set(rkey(record.address, request.digest), { intentId: result.intentId, wireId: result.wireId, at: Date.now() });
      status = 'The payment was sent to the network. It shows in the vault history once it is in a block (Refresh).';
    } else { status = result.message || 'The network refused this payment.'; sessionLog.log('vault', `Vault payment refused: ${status}`, { error: true }); loggedStatus = status; }
  } catch (error) {
    if (gen === generation) { status = error.message || 'The payment could not be sent.'; sessionLog.log('vault', status, { error: true }); loggedStatus = status; }
  } finally {
    if (gen === generation) { busy = false; render(); }
  }
}

// ── rendering: the panel ─────────────────────────────────────────────────

function showPanel() {
  if (!panel) return;
  const ready = !!client && client.state === 'ready' && client.vaultable;
  const nodusSelected = $('chain')?.value === NODUS_ASSET.chain;
  panel.hidden = !(ready && nodusSelected);
  const nav = $('nav-vaults');
  if (nav) nav.hidden = panel.hidden;
}

function render({ keepTyped = false } = {}) {
  showPanel();
  if (!root) return;
  if (!client) { root.replaceChildren(); return; }
  // Each new status line shown also goes to the session log.
  if (status && status !== loggedStatus) sessionLog.log('vault', status);
  loggedStatus = status;
  const items = [el('p', { className: 'hint page-note', text: 'A shared vault holds NODUS that can only be spent when enough of its members approve. Each member approves from their own wallet.' })];
  const line = el('p', { className: 'hint vault-status', text: status });
  line.setAttribute('role', 'status'); line.setAttribute('aria-live', 'polite');
  items.push(line);
  // keepTyped (an Open / Refresh's redraws): what was typed in the payment
  // form, and which field had the focus, survive the panel being drawn again
  // (the cursor position inside the field is not kept);
  // the keys carry the vault address, so nothing moves to another vault.
  const typed = keepTyped ? [...root.querySelectorAll('input[data-keep]')].map(n => ({ key: n.dataset.keep, value: n.value, focused: n === document.activeElement })) : [];
  if (view === 'vault' && current && vaults.has(current)) items.push(renderVault(vaults.get(current)));
  else if (view === 'create') items.push(renderCreate());
  else if (view === 'watch') items.push(renderWatch());
  else items.push(renderList());
  root.replaceChildren(...items);
  for (const t of typed) {
    const node = [...root.querySelectorAll('input[data-keep]')].find(n => n.dataset.keep === t.key);
    if (!node) continue;
    if (!node.value) node.value = t.value;
    if (t.focused) node.focus();
  }
  const buttons = root.querySelectorAll('button');
  for (const b of buttons) if (busy && !b.dataset.always) b.disabled = true;
  if (!busy) { pressed = null; return; }
  const shown = pressed && buttons[pressed.index];
  if (shown && shown.textContent === pressed.label) { shown.textContent = 'Preparing…'; shown.setAttribute('aria-busy', 'true'); }
}

// ── rendering: small parts (0.1.83 design) ──────────────────────────────
// Every text below is set through textContent (el); no inline style (the
// pages' CSP is style-src 'self'): the approvals bar is a <progress>.

// A chip beside a title: "2 of 3 approvals", "Watching only".
function chip(text, kind = '') {
  const node = el('span', { className: 'vault-chip', text });
  if (kind) node.dataset.kind = kind;
  return node;
}
// The round mark of a member: the first letters of the chain name the
// reverse lookup CONFIRMED (F5 — never a name only typed here), otherwise
// the first two characters of the ID. Decoration only (aria-hidden).
function avatar(fp) {
  const chain = names.get(fp);
  const letters = chain ? [...chain.replace(/[^\p{L}\p{N}]/gu, '')].slice(0, 2).join('') : '';
  const node = el('span', { className: 'vault-avatar', text: (letters || fp.slice(0, 2)).toUpperCase() });
  node.setAttribute('aria-hidden', 'true');
  return node;
}
// One member: mark, name (who — F5 wording kept; this wallet's own row shows
// its confirmed chain name or short ID with a "you" badge), the full ID.
function memberRow(fp) {
  const own = fp === ownFp;
  const chain = names.get(fp);
  const title = own ? (chain ? `${chain} · ${shortId(fp)}` : shortId(fp)) : who(fp);
  const row = el('div', { className: 'vault-member' }, avatar(fp),
    el('span', { className: 'vault-member-main' }, el('strong', { text: title }), el('small', { className: 'vault-mono', text: fp })));
  if (own) row.append(el('span', { className: 'vault-you', text: 'you' }));
  return row;
}
// An address in a monospace box with a Copy button. Copy is not an action of
// the panel (btn: it does not mark the pressed button), and its result is
// said beside it.
function addressBox(address, labelText) {
  const note = el('span', { className: 'vault-copy-note' });
  note.setAttribute('aria-live', 'polite');
  const copy = el('button', { className: 'secondary small', text: 'Copy' });
  copy.type = 'button';
  copy.setAttribute('aria-label', 'Copy the vault address');
  copy.onclick = async () => {
    try { await navigator.clipboard.writeText(address); note.textContent = 'Copied.'; }
    catch { note.textContent = 'Could not copy. Select the address and copy it by hand.'; }
  };
  return el('div', { className: 'vault-address-box' },
    el('span', { className: 'vault-label', text: labelText }),
    el('code', { className: 'vault-address', text: address }),
    el('span', { className: 'vault-copy-row' }, copy, note));
}
// A label / value row of a reviewed payment (renderReviewRows).
function fact(label, value, note = '', mono = false) {
  const dd = el('dd', {}, el('span', { text: value }));
  if (note) dd.append(el('small', { className: mono ? 'vault-mono' : 'vault-fact-note', text: note }));
  return el('div', { className: 'vault-fact' }, el('dt', { text: label }), dd);
}
// The balance: large, then what can be spent now.
function balanceBlock(bal, { compact = false } = {}) {
  const box = el('div', { className: compact ? 'vault-money vault-money-compact' : 'vault-money' });
  if (!compact) box.append(el('span', { className: 'vault-label', text: 'Balance' }));
  if (bal) box.append(el('strong', { className: 'vault-amount', text: nodus(bal.total) }), el('span', { className: 'vault-spendable', text: `${nodus(bal.spendable)} spendable now` }));
  else box.append(el('strong', { className: 'vault-amount vault-amount-unknown', text: 'Not read yet' }), el('span', { className: 'vault-spendable', text: compact ? 'Open the vault to read its balance.' : 'Refresh to read it from the Nodus node.' }));
  return box;
}
const approvalsChip = record => chip(`${record.m} of ${record.n} approvals`);

function renderList() {
  const rows = [...vaults.values()];
  const actions = el('div', { className: 'vault-actions' },
    btn('Create a shared vault', () => { view = 'create'; status = ''; createInfo = null; render(); }, ''),
    btn('Watch a vault', () => { view = 'watch'; status = ''; render(); }));
  if (!rows.length) {
    return el('div', { className: 'stake-block vault-list vault-empty' },
      el('h4', { text: 'Your shared vaults' }),
      el('p', { className: 'vault-empty-lead', text: 'You are not a member of any shared vault yet.' }),
      el('p', { className: 'hint', text: 'A shared vault holds NODUS together with other people. A payment leaves it only when enough of its members approve it, each from their own wallet. Create one with the people you choose, or watch one whose vault code a member gave you.' }),
      actions);
  }
  const grid = el('div', { className: 'vault-grid' });
  for (const record of rows) {
    const title = el('h5', { text: labelOf(record) });
    const chips = el('div', { className: 'vault-chips' }, approvalsChip(record), record.watch ? chip('Watching only', 'watch') : null);
    const open = btn('Open', () => { current = record.address; view = 'vault'; status = ''; render(); void refresh(record.address, { reviewRequests: true }); }, 'small');
    open.setAttribute('aria-label', `Open ${labelOf(record)}`);
    grid.append(el('article', { className: 'vault-tile' },
      el('div', { className: 'vault-tile-head' }, title, chips),
      el('p', { className: 'vault-tile-rule', text: `${record.m} of ${record.n} members must approve a payment.` }),
      balanceBlock(balances.get(record.address), { compact: true }),
      el('div', { className: 'vault-tile-foot' }, open)));
  }
  return el('div', { className: 'stake-block vault-list' }, el('h4', { text: 'Your shared vaults' }), grid, actions);
}

function field(labelText, control) {
  const id = `vaults-f-${Math.random().toString(36).slice(2, 10)}`;
  control.id = id;
  const label = el('label', { text: labelText });
  label.htmlFor = id;
  return [label, control];
}
function input(value = '', attrs = {}) {
  const node = document.createElement('input');
  node.value = value; node.autocomplete = 'off'; node.spellcheck = false;
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  return node;
}

function renderCreate() {
  const box = el('div', { className: 'stake-block vault-form' }, el('h4', { text: 'Create a shared vault' }),
    el('p', { className: 'hint', text: 'Choose the members and how many of them must approve a payment. The vault address is computed on this device from the members’ keys.' }));
  const label = input('', { maxlength: '48', placeholder: 'Family savings' });
  const members = document.createElement('textarea');
  members.rows = 3; members.spellcheck = false; members.placeholder = 'one per line: a chain name, or an ID';
  box.append(...field('Vault name (only for you and the members)', label));
  box.append(...field('Other members', members));
  box.append(el('p', { className: 'hint vault-field-hint', text: `You are a member. Add up to ${VAULT_MAX_MEMBERS - 1} others by their chain name or their ID.` }));
  const picked = new Set();
  if (messagesOpen()) {
    const contacts = host.contacts();
    if (contacts.length) {
      const list = el('div', { className: 'vault-contacts' });
      for (const c of contacts) {
        const check = document.createElement('input'); check.type = 'checkbox';
        check.onchange = () => { if (check.checked) picked.add(c.fp); else picked.delete(c.fp); };
        const row = el('label', { className: 'check vault-contact' }, check, el('span', { text: c.name }));
        list.append(row);
      }
      box.append(el('p', { className: 'vault-subhead', text: 'Or pick from your contacts:' }), list);
    }
  }
  const approvals = document.createElement('select');
  for (let i = 1; i <= VAULT_MAX_MEMBERS; i++) approvals.append(new Option(String(i), String(i)));
  approvals.value = '2';
  box.append(...field('Approvals needed to spend', approvals));
  box.append(el('p', { className: 'hint vault-field-hint', text: 'For example, 2 means any two members together can spend. It cannot be changed later: a new vault would be needed.' }));
  const actions = el('div', { className: 'vault-actions' },
    btn('Check members', () => void checkMembers({ label: label.value, members: members.value, contacts: [...picked], m: approvals.value }), ''),
    btn('Back', () => { view = 'list'; createInfo = null; status = ''; render(); }));
  box.append(actions);
  if (createInfo) {
    const { info } = createInfo;
    const preview = el('div', { className: 'vault-members' });
    for (const fp of info.members) preview.append(memberRow(fp));
    box.append(el('div', { className: 'vault-preview' },
      el('div', { className: 'vault-tile-head' }, el('h5', { text: 'The new vault' }), chip(`${info.m} of ${info.n} approvals`)),
      el('p', { className: 'hint', text: `${info.m} of ${info.n} members must approve a payment.` }),
      preview,
      addressBox(info.address, 'Vault address (computed on this device from the members’ keys)'),
      el('div', { className: 'vault-actions' }, btn('Create vault', () => void createVault(), ''))));
  }
  return box;
}

function renderWatch() {
  const box = el('div', { className: 'stake-block vault-form' }, el('h4', { text: 'Watch a vault' }));
  box.append(el('p', { className: 'hint', text: 'Paste a vault code a member gave you to see its balance. Its coins and history are shown only to its members; if you are not one you can only watch its balance.' }));
  const code = document.createElement('textarea'); code.rows = 3; code.spellcheck = false; code.className = 'vault-mono';
  const label = input('', { maxlength: '48' });
  box.append(...field('Vault code', code), ...field('Name (optional)', label));
  box.append(el('div', { className: 'vault-actions' },
    btn('Add', () => void watchVault({ code: code.value, label: label.value }), ''),
    btn('Back', () => { view = 'list'; status = ''; render(); })));
  return box;
}

function renderReviewRows(record, review) {
  const list = el('dl', { className: 'vault-facts' });
  for (const out of review.outputs) {
    if (out.change) list.append(fact('Change back to this vault', nodus(out.amount)));
    else {
      list.append(fact('Pay to', HEX128.test(out.owner) ? who(out.owner) : out.owner, out.owner, true));
      list.append(fact('Amount', nodus(out.amount)));
    }
  }
  list.append(fact('Network fee', nodus(review.fee), 'paid from the vault'));
  const left = blocksLeft(review);
  list.append(review.expired
    ? fact('Valid until', `Expired at block ${review.expiryHeight}`, `The network passed block ${review.expiryHeight}. Propose it again.`)
    : fact('Valid until', `Block ${review.expiryHeight}`, `${left} blocks from now; after that it must be proposed again.`));
  // F1: the module refused the review unless every coin it spends is one of
  // this vault's own coins (nodus-send-wasm.c nsw_ms_inputs_owned)
  list.append(fact('Coins checked', `All ${review.inputs.length} coins it spends belong to this vault.`));
  return list;
}

function renderVault(record) {
  const page = el('div', { className: 'vault-view' });
  const bal = balances.get(record.address);
  const read = reads.get(record.address);
  page.append(btn('← All shared vaults', () => { view = 'list'; current = null; draft = null; status = ''; render(); }, 'secondary small vault-back'));

  // the header card: name, rule, balance, address, actions
  const hero = el('section', { className: 'stake-block vault-hero' });
  hero.append(el('div', { className: 'vault-hero-head' },
    el('h4', { text: labelOf(record) }),
    el('div', { className: 'vault-chips' }, approvalsChip(record), record.watch ? chip('Watching only', 'watch') : null)));
  hero.append(el('p', { className: 'hint vault-rule', text: `${record.m} of ${record.n} members must approve a payment.${record.watch ? ' You are watching this vault; you cannot approve its payments.' : ''}` }));
  hero.append(el('div', { className: 'vault-hero-body' }, balanceBlock(bal), addressBox(record.address, 'Vault address (receive NODUS here)')));
  const top = el('div', { className: 'vault-actions vault-toolbar' }, btn('Refresh', () => void refresh(record.address)));
  if (messagesOpen() && !record.watch) top.append(btn('Share with members', () => void shareVault(record)));
  if (!record.foundation) top.append(btn('Remove from this list', () => void removeVault(record), 'secondary small vault-remove'));
  hero.append(top);
  if (record.watch) hero.append(el('p', { className: 'notice vault-notice', text: 'Only the vault’s members can see its coins and history.' }));
  else if (read?.unsupported) hero.append(el('p', { className: 'notice vault-notice', text: 'This Nodus node is not updated yet for shared vaults. Try again later.' }));
  else if (read?.truncated) hero.append(el('p', { className: 'notice vault-notice', text: 'This vault has more coins than this page can hold; payments can use only part of them.' }));
  page.append(hero);

  // members
  const members = el('div', { className: 'vault-members' });
  for (const fp of record.members) members.append(memberRow(fp));
  page.append(el('section', { className: 'stake-block' }, el('h4', { text: `Members (${record.members.length})` }), members));

  // payment requests
  const items = itemsFor(record);
  if (draft && draft.address === record.address && !items.requests.has(draft.request.digest)) items.requests.set(draft.request.digest, { request: draft.request, from: '', at: Date.now(), draft: true });
  // open ones on top, newest first; paid / spent / expired / not valid in a
  // collapsed "Finished requests" section below them (0.1.85)
  if (items.requests.size) {
    const box = el('section', { className: 'stake-block' }, el('h4', { text: 'Payment requests' }));
    const all = [...items.requests]
      .map(([digest, item]) => ({ digest, item, state: requestStateOf(record, digest) }))
      .sort((a, b) => b.item.at - a.item.at);
    const open = all.filter(r => !FINISHED.has(r.state));
    const finished = all.filter(r => FINISHED.has(r.state));
    const openList = el('div', { className: 'vault-open-requests' });
    for (const r of open) openList.append(renderRequest(record, r.digest, r.item, items, r.state));
    if (!open.length) openList.append(el('p', { className: 'hint', text: 'No open payment requests.' }));
    box.append(openList);
    if (finished.length) {
      const details = el('details', { className: 'vault-finished' }, el('summary', { text: `Finished requests (${finished.length})` }));
      // the panel is drawn again during every action: the section stays as
      // the user left it
      details.open = finishedOpen.has(record.address);
      details.addEventListener('toggle', () => { if (details.open) finishedOpen.add(record.address); else finishedOpen.delete(record.address); });
      for (const r of finished) details.append(renderRequest(record, r.digest, r.item, items, r.state));
      box.append(details);
    }
    page.append(box);
  }

  // propose
  if (!record.watch) {
    const form = el('section', { className: 'stake-block vault-form' }, el('h4', { text: 'Propose a payment' }));
    if (!messagesOpen()) form.append(el('p', { className: 'hint', text: 'Proposing and approving vault payments works in Nodus Connect, where the members are told by message.' }));
    else {
      const to = input('', { placeholder: 'chain name or Nodus address', 'data-keep': `${record.address}|to` });
      const amount = input('', { inputmode: 'decimal', placeholder: '0.00', 'data-keep': `${record.address}|amount` });
      form.append(el('div', { className: 'vault-form-grid' },
        el('div', { className: 'vault-form-cell' }, ...field('Pay to', to)),
        el('div', { className: 'vault-form-cell' }, ...field('Amount (NODUS)', amount))),
      el('p', { className: 'hint vault-field-hint', text: `You approve it first; then ${Math.max(record.m - 1, 0)} more member(s) must approve before it can be sent. It must be completed within about 90 blocks.` }),
      el('div', { className: 'vault-actions' }, btn('Prepare', () => void prepareRequest(record, { to: to.value, amount: amount.value }), '')));
    }
    page.append(form);
  }

  // history: the node's page of the vault address (one node's own index,
  // not consensus — src/nodus/history.js), each row in the words the
  // wallet's own NODUS history uses (nodusHistoryRow)
  if (read?.history) page.append(renderHistory(read.history));
  return page;
}

// The vault's history page (parseAddrHistory's answer): what the node keeps
// first ("History from block N" when it keeps nothing older, or that it
// keeps no address history), then the rows, newest first — laid out like
// the wallet's Activity rows.
function renderHistory(page) {
  const box = el('section', { className: 'stake-block vault-history' }, el('h4', { text: 'History' }));
  const notes = [];
  if (!page.enabled && page.fromHeight === 0n) notes.push('This Nodus node does not keep address history.');
  else {
    if (page.fromHeight === 0n) notes.push('This Nodus node keeps no address history yet.');
    if (!page.enabled) notes.push('This Nodus node does not keep address history right now, so the newest entries may be missing.');
    if (page.fromHeight > 1n) notes.push(`History from block ${page.fromHeight}: this node keeps nothing older.`);
    if (page.entries.length >= NODUS_HISTORY_LIMIT) notes.push(`The newest ${NODUS_HISTORY_LIMIT} entries, as reported by one Nodus node.`);
  }
  if (notes.length) box.append(el('p', { className: 'hint vault-history-note', text: notes.join(' ') }));
  if (!page.entries.length) { box.append(el('p', { className: 'stake-empty', text: 'Nothing in this vault’s history on this node.' })); return box; }
  const list = el('div', { className: 'activity-list' });
  for (const entry of page.entries) {
    const row = nodusHistoryRow(entry, { names });
    const main = el('span', { className: 'activity-main' }, el('strong', { text: row.title }));
    if (row.detail) main.append(el('small', { text: row.detail }));
    const side = el('span', { className: 'activity-side' });
    if (row.amount) side.append(el('strong', { className: 'vault-history-amount', text: `${row.sign}${row.amount}` }));
    side.append(el('small', { text: `block ${row.height}` }));
    list.append(el('div', { className: `activity-row${row.dir ? ` history-dir-${row.dir}` : ''}` }, main, side));
  }
  box.append(list);
  return box;
}

// The pill text of each request state (core.js requestState, plus 'sent'
// below), and what it means when the pill alone does not say it.
const STATE_PILL = { paid: 'Paid', spent: 'Coins spent', expired: 'Expired', ready: 'Ready to send', waiting: 'Waiting for approvals', sent: 'Sent', refused: 'Not valid' };
const STATE_NOTE = {
  paid: 'Paid.', spent: 'Its coins are spent — it was paid, or another payment used them.', expired: 'Expired — propose again.',
  ready: 'Approved — ready to send.', waiting: '', sent: 'Sent to the network.'
};
// The states shown in "Finished requests": nothing more can be done with
// them. 'refused' is a request the module's last review refused (its text
// is on the card); "Check again" stays on it.
const FINISHED = new Set(['paid', 'spent', 'expired', 'refused']);

// A request's state on the page: 'refused' (the last review was refused),
// 'unreviewed', or stateOf's answer — 'sent' when this wallet sent it and
// it is neither paid nor spent yet.
function requestStateOf(record, digest) {
  const key = rkey(record.address, digest);
  if (refusals.has(key)) return 'refused';
  const rv = reviews.get(key);
  if (!rv) return 'unreviewed';
  // F2: only the approvals the module verified at the last check count
  const verified = Array.isArray(rv.verifiedSigners) ? rv.verifiedSigners : [];
  const plain = stateOf(record, key, rv, verified.length);
  return sent.has(key) && plain !== 'paid' && plain !== 'spent' ? 'sent' : plain;
}

// When the request's message arrived (its `at`, this device's clock, shown
// in local time); this wallet's own unsent draft says it was prepared here.
function arrivedLine(item) {
  const text = item.draft ? 'Prepared here'
    : Number.isFinite(item.at) ? `Received ${new Date(item.at).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })}` : '';
  return text ? el('p', { className: 'hint vault-received', text }) : null;
}

function renderRequest(record, digest, item, items, state) {
  const key = rkey(record.address, digest);
  const card = el('article', { className: 'vault-request' });
  const from = item.from ? who(item.from) : 'you';
  const title = el('h5', { text: `Payment request from ${from}` });
  if (state === 'refused') {
    // the module's own words, as they are; nothing to approve or send
    const pill = el('span', { className: 'status-badge vault-state', text: STATE_PILL.refused });
    pill.dataset.status = 'refused';
    card.dataset.state = 'refused';
    const actions = el('div', { className: 'vault-actions' }, btn('Check again', () => void review(record, item.request)));
    if (item.draft) actions.append(btn('Discard', () => { draft = null; reviews.delete(key); refusals.delete(key); render(); }));
    card.append(el('div', { className: 'vault-request-head' }, title, pill), arrivedLine(item),
      el('p', { className: 'notice vault-notice vault-refusal', text: refusals.get(key) }), actions);
    return card;
  }
  const rv = reviews.get(key);
  if (!rv) {
    const pill = el('span', { className: 'status-badge vault-state', text: 'Not reviewed yet' });
    pill.dataset.status = 'unreviewed';
    card.append(el('div', { className: 'vault-request-head' }, title, pill), arrivedLine(item),
      el('p', { className: 'hint', text: 'Review it to see what it pays: the page shows only what the request itself says.' }),
      el('div', { className: 'vault-actions' }, btn('Review', () => void review(record, item.request), '')));
    return card;
  }
  // F2: only the approvals the module verified at the last check count
  const verified = Array.isArray(rv.verifiedSigners) ? rv.verifiedSigners : [];
  const pill = el('span', { className: 'status-badge vault-state', text: STATE_PILL[state] });
  pill.dataset.status = state;
  card.dataset.state = state;
  card.append(el('div', { className: 'vault-request-head' }, title, pill), arrivedLine(item));
  if (STATE_NOTE[state]) card.append(el('p', { className: 'vault-state-note', text: STATE_NOTE[state] }));
  const counted = Math.min(verified.length, rv.approvals);
  const progressText = `${counted} of ${rv.approvals} approvals checked`;
  const bar = document.createElement('progress');
  bar.className = 'vault-progress';
  bar.max = Math.max(Number(rv.approvals) || 1, 1); bar.value = counted;
  bar.setAttribute('aria-label', progressText);
  card.append(el('div', { className: 'vault-approvals' }, el('span', { className: 'vault-approvals-text', text: progressText }), bar));
  if (rv.refused) card.append(el('p', { className: 'notice vault-notice', text: `${rv.refused} approval item(s) did not check out and are not counted.` }));
  card.append(el('p', { className: 'hint vault-approved-by', text: verified.length ? `Approved by ${verified.map(who).join(', ')}. “Check again” counts approvals that arrived since.` : '“Check again” counts approvals that arrived since.' }),
    renderReviewRows(record, rv));
  const actions = el('div', { className: 'vault-actions' });
  if (state !== 'paid' && state !== 'spent' && state !== 'expired' && state !== 'sent') {
    if (!ownApprovals.has(key) && !items.approvedHere.has(digest) && !verified.includes(ownFp) && rv.member && !record.watch && messagesOpen()) actions.append(btn(item.draft ? 'Approve and send to members' : 'Approve', () => void approve(record, item.request, { isNew: !!item.draft }), ''));
    if (state === 'ready') actions.append(btn('Send payment', () => void sendPayment(record, item.request, items), ''));
    actions.append(btn('Check again', () => void review(record, item.request)));
  }
  if (item.draft) actions.append(btn('Discard', () => { draft = null; reviews.delete(key); refusals.delete(key); render(); }));
  if (actions.childElementCount) card.append(actions);
  return card;
}

// ── rendering: the cards in Messages ────────────────────────────────────

// "Open vault" from a card: an in-page link to the panel (the Nodus Connect
// shell shows the screen holding it, src/connect-main.js); the panel lives
// in the NODUS account area, so NODUS is selected first (the wallet's own
// network selector, as a person would).
function openLink(address) {
  const link = el('a', { text: 'Open vault' });
  link.href = '#vault-panel';
  link.onclick = () => {
    const select = $('chain');
    if (select && select.value !== NODUS_ASSET.chain) { select.value = NODUS_ASSET.chain; select.dispatchEvent(new Event('change')); }
    current = address; view = 'vault'; status = '';
    render();
    void refresh(address, { reviewRequests: true });
  };
  return link;
}

const payloadView = {
  preview(text) {
    const item = decodeVaultMessage(text);
    if (!item) return null;
    return { share: 'Shared vault', request: 'Vault payment request', approval: 'Vault payment approval', invalid: 'Vault item (unreadable)' }[item.kind];
  },
  card(message) {
    const item = decodeVaultMessage(message.text);
    if (!item) return null;
    const card = el('div', { className: 'message-text vault-card' });
    if (item.kind === 'invalid') { card.append(el('strong', { text: 'A vault item this page cannot read.' })); return card; }
    if (item.kind === 'approval' || item.kind === 'request') {
      const record = vaults.get(item.vault);
      // F2: an item from someone who is not a member of the vault it names
      // is ignored (collectVaultItems skips it too)
      const stranger = record && message.dir !== 'out' && !record.members.includes(message.fp);
      card.append(el('strong', { text: item.kind === 'approval' ? 'Approval for a vault payment' : 'Vault payment request' }));
      if (!record) card.append(el('p', { text: 'For a vault that is not in your list.' }));
      else if (stranger) card.append(el('p', { text: `For ${labelOf(record)}, but sent by someone who is not a member of it. It is ignored.` }));
      else {
        card.append(el('p', { text: item.kind === 'approval' ? `For ${labelOf(record)}. It counts only once the vault checks it.` : `For ${labelOf(record)}. Review it in Shared vaults (NODUS); it shows only what the request itself says.` }));
        card.append(openLink(record.address));
      }
      return card;
    }
    // share
    const shape = vaultCodeShape(item.code);
    card.append(el('strong', { text: `Shared vault${item.label ? `: ${item.label}` : ''}` }), el('p', { text: `${shape.m} of ${shape.n} members must approve a payment.` }));
    if (message.dir === 'out') { card.append(el('p', { text: 'You shared this vault.' })); return card; }
    const s = shareStates.get(item.code);
    const already = [...vaults.values()].some(r => r.code === item.code);
    if (already || s?.state === 'added') card.append(el('p', { text: 'This vault is in your list.' }));
    else if (!s) card.append(btn('Add vault', () => void checkShare({ ...item, from: message.fp })));
    else if (s.state === 'checking') card.append(el('p', { text: 'Reading the vault…' }));
    else if (s.state === 'adding') card.append(el('p', { text: 'Adding the vault…' }));
    else if (s.state === 'error') card.append(el('p', { text: s.error }));
    else if (s.state === 'confirm') {
      const list = el('ul', {});
      for (const fp of s.info.members) list.append(el('li', { text: who(fp) }));
      card.append(el('p', { text: `Members (${s.info.m} of ${s.info.n} must approve):` }), list,
        el('p', { text: 'Address:' }), el('code', { className: 'vault-address', text: s.info.address }),
        btn('Add this vault', () => void addShared(item.code)));
    }
    return card;
  }
};

// ── mount + extension ────────────────────────────────────────────────────

// panelNode: #vault-panel; rootNode: #vaults-root; messagesHost: Messages'
// vaultHost (Nodus Connect) or null (the wallet page).
export function mountVaults({ panelNode, rootNode, messagesHost = null }) {
  panel = panelNode; root = rootNode; host = messagesHost;
  $('chain')?.addEventListener('change', showPanel);
  if (host) {
    host.setPayloadView(payloadView);
    // Messages opened (its kept vaults load) or new items arrived (the
    // panel's requests and approvals are drawn again).
    host.onChange(() => {
      if (!client) return;
      const gen = generation;
      void loadVaults(gen).then(() => { if (gen === generation) render(); });
    });
  }
  render();
}

export const vaultExtension = {
  nodusReady(detail) { void start(detail); },
  nodusClosing() { reset(); },
  nodusUnavailable() { reset(); },
  vaultDeleting() { reset(); },
  locked() { reset(); }
};
