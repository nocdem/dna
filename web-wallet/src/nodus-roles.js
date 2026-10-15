// Nodus Connect — the "Nodus" page (#nodus-roles; More → Nodus): become a
// witness, become a storage node, and "My registered nodes" — this wallet's
// witnesses and storage nodes on one screen, where it stops a witness
// (operator 2026-10-13 "Ekle") or leaves storage (operator 2026-10-15: the
// storage nodes moved there from "Become a storage node"). There is no "change your
// node's key": the khan removed key ROTATE from HF-6 (decision
// docs/plans/decisions/2026-10-13-kurultay-18-summary.md item 1 — a key
// used once is never usable again); a witness moves to a new key by
// stopping here and becoming a witness again from the new node.
// src/app.js wallet pages show the page; this module fills its
// panel. Connect site only: src/connect-main.js mounts it and registers its
// extension; the wallet site (index.html) has none of its elements and
// never imports it, and nothing here touches the document at load.
//
// Design docs/plans/2026-10-12-connect-hf6-screens-design.md rev 1 (§1 what
// the user does, §2 the consent checks, §3 the gates, G1-G4, "Timing
// facts"); docs/plans/2026-10-03-hf5-validator-owner-stake-design.md rev 6
// §6.1 (the node consent), §9 (the three screens, place: Settings →
// "Nodus"; operator: "Yanlış olmaması lazım"), §11 (storage owner / node
// split); decisions/2026-10-09-kurultay-16-hf6-storage-summary.md. Operator
// 2026-10-12: the screens are shown BEFORE HF-6 is in force; sending stays
// disabled until the node runs the HF-6 generation.
//
// HOW IT IS SAFE (design G1-G4):
// - The consent the user pastes is checked by the MODULE (synchronous, no
//   network): op, chain, owner = this wallet, subject, expiry window, the
//   node's signature (src/adapters/nodus.js checkConsent). Review is
//   offered only when every line passed; the build re-checks it.
// - The Review shows only what the module read back from the SIGNED bytes
//   (src/adapters/nodus.js prepareHf6): the bond, the node key's
//   fingerprint (prominent — design G2: an attacker's consent for your
//   witness passes every check, so the user compares the fingerprint with
//   what their node printed), the fee and the balance after.
// - The owner is always THIS wallet's own key (a single-key owner). A shared
//   vault is never an owner here: no builder supports a multisig owner yet
//   (design §3).
// - Gate: below the HF-6 generation (hf6Rules.generation vs the node's
//   rulesetInfo().generation), or when the node does not say, the amber
//   note shows and no Review / Confirm is enabled; the checks still run.
// - Bonds: the witness bond floor and the exact storage bond are chain
//   parameters (19 / 21), read from the node on every refresh (hf6Bonds,
//   BUGS W-20) — the figures shown and the amount asked for; when they
//   cannot be read the page says so and becoming a witness or a storage
//   node offers no Review. Leaving storage re-reads the node's row first.
// - A consent that ends before the transaction could be included, and a
//   node key the page could not check against the COMPLETE witness list,
//   fail their check lines (BUGS W-21): no Review.
// - Times are BLOCK HEIGHTS computed from the chain constants the module
//   carries (epoch length, minimum tenure, storage exit lock) — earliest
//   heights only, never hours or days; without a constant, no number. When
//   a witness stops, no height can be computed (it leaves at the first
//   boundary where it is no longer in the set taking effect — usually one or
//   two boundaries, nodus_witness_v2_epoch.c v2ep_graduate): the locks are
//   given as BLOCK COUNTS after it leaves (the witness unbond lock and the
//   delegation lock, from the module's constants).
// - Every text through textContent; no innerHTML. Nothing is stored on the
//   device (decision 2026-10-02-device-cache-only-when-saved: the page keeps
//   its state in memory and clears it on lock).
import { formatUnits } from './core.js';
import { NODUS_ASSET } from './nodus/network.js';
import {
  HF6_NOT_YET_TEXT, parseHf6Rules, parseRulesetInfo, parseBalance, parseValidators, parseStakingRules,
  checkConsent, storageNodes, prepareHf6, shortKey, UNSTAKE_STATUSES, hf6Bonds, expiryHeightFor,
  consentEndsBefore, CONSENT_ENDS_EARLY_TEXT
} from './adapters/nodus.js';

// ── pure helpers (no DOM; test/nodus-roles.test.js) ─────────────────────

// The --expiry suggested in the node command: tip + consentWindow − 10.
// Why −10: the module checks `expiry − tip ≤ consentWindow` (720) against
// the COIN LISTING's tip when it builds (nodus-send-wasm.c nsw_hf6_build),
// and that listing may come from a node a few blocks behind or ahead of the
// one whose tip this page read; 10 blocks of margin keep a consent made from
// this suggestion inside the window at build time. null: tip unknown (0) or
// a window too small to leave the margin.
export const EXPIRY_MARGIN = 10n;
export function suggestExpiry(tip, consentWindow) {
  if (typeof tip !== 'bigint' || typeof consentWindow !== 'bigint' || tip <= 0n || consentWindow <= EXPIRY_MARGIN) return null;
  return tip + consentWindow - EXPIRY_MARGIN;
}
// A commission typed in percent ("10", "12.5", "0.25") -> basis points
// (BigInt). maxBps: the chain's maximum (stakingRules.commissionMaxBps), or
// null when the module does not carry it (the module refuses above it).
export function percentToBps(text, maxBps = null) {
  const value = typeof text === 'string' ? text.trim() : '';
  const m = /^(\d{1,3})(?:\.(\d{1,2}))?$/.exec(value);
  const maxText = maxBps === null ? '' : ` and ${Number(maxBps) / 100}%`;
  if (!m) throw new Error(`Enter a commission between 0%${maxText || ' and the maximum'}, with at most two decimals.`);
  const bps = BigInt(m[1]) * 100n + BigInt((m[2] || '').padEnd(2, '0') || '0');
  if (maxBps !== null && bps > maxBps) throw new Error(`The commission can be at most ${Number(maxBps) / 100}%.`);
  return bps;
}
// Whether sending is open: the node's rule-set generation (BigInt or
// decimal string; undefined / null = the node did not say) is at least the
// generation that carries the HF-6 calls.
export function gateOpen(nodeGeneration, hf6Generation) {
  let g;
  if (typeof nodeGeneration === 'bigint') g = nodeGeneration;
  else if (typeof nodeGeneration === 'string' && /^[1-9]\d{0,19}$/.test(nodeGeneration)) g = BigInt(nodeGeneration);
  else return false;
  const need = typeof hf6Generation === 'bigint' ? hf6Generation : Number.isSafeInteger(hf6Generation) && hf6Generation > 0 ? BigInt(hf6Generation) : null;
  return need !== null && g >= need;
}
// This wallet's witnesses: the rows of the validator list that carry a
// generation-4 owner equal to this wallet's fingerprint.
export function ownWitnesses(validators, fingerprint) {
  if (!Array.isArray(validators) || typeof fingerprint !== 'string' || !fingerprint) return [];
  return validators.filter(v => v && v.hasV2 === true && v.ownerFp === fingerprint);
}
// Whether "Stop being a witness" is offered for one of this wallet's
// witnesses: the chain accepts the generation-4 UNSTAKE only for a row that
// is ACTIVE or ELIGIBLE (rtn_unstake2_exec; a leaving one is refused).
export function canStopWitness(v) {
  return !!v && UNSTAKE_STATUSES.includes(v.status);
}
// A lock of `epochs` epochs as a block count (epochs × E, BigInt); null
// without either constant.
export function lockBlocks(epochs, E) {
  if (typeof epochs !== 'bigint' || typeof E !== 'bigint' || E <= 0n) return null;
  return epochs * E;
}
// The lists each screen reads after the node's facts: becoming a witness
// needs the witness list (the node-key check line, keyCheckLine); "My
// registered nodes" shows both of this wallet's lists. Becoming a storage
// node reads neither: its consent flow does not use the storage list, and
// leaving storage (the only reader of that list, with its Review) is on
// "My registered nodes".
export const SCREEN_LISTS = Object.freeze({
  home: Object.freeze({ witnesses: false, storage: false }),
  witness: Object.freeze({ witnesses: true, storage: false }),
  storage: Object.freeze({ witnesses: false, storage: false }),
  nodes: Object.freeze({ witnesses: true, storage: true })
});
// The page's own consent check lines (BUGS W-21), added after the module's
// seven; each fails closed — Review is offered only when every line passed.
// consentMarginLine: the consent must last at least until the last block
// this transaction could be included in (`expiryHeight`, BigInt — the
// height a build made now would request, src/adapters/nodus.js
// expiryHeightFor; null = not known). A consent ending earlier was a
// warning on the Review (nodus-cli.c cmd_v2_stake's); now it blocks, and
// prepareHf6 refuses it too (consentEndsBefore).
export function consentMarginLine(consentExpiry, expiryHeight) {
  if (typeof consentExpiry !== 'bigint' || typeof expiryHeight !== 'bigint') return { id: 'margin', ok: false, detail: 'Whether this consent lasts long enough could not be checked: the network’s current block height is not known.' };
  if (consentEndsBefore(consentExpiry, expiryHeight)) return { id: 'margin', ok: false, detail: CONSENT_ENDS_EARLY_TEXT };
  return { id: 'margin', ok: true, detail: `This consent lasts until block ${block(consentExpiry)}, not before the last block this transaction could be included in (${block(expiryHeight)}).` };
}
// keyCheckLine: a stake's node key is not already a witness's key (the one
// check the module leaves to the chain, design §2 item 7), from the witness
// list `witnesses` ({ rows, truncated, error } | null while reading).
// `state`: 'taken' (the key is in the list), 'free' (the COMPLETE list does
// not have it) or 'unknown' (the list is being read, could not be read, or
// is only part of the witnesses) — 'unknown' fails, never passes.
export function keyCheckLine(witnesses, nodeFp) {
  const unknown = why => ({ id: 'key', ok: false, state: 'unknown', detail: `Whether this node key is already a witness’s key could not be checked: ${why}` });
  if (!witnesses) return unknown('the witness list is still being read.');
  if (witnesses.error) return unknown(`the witness list could not be read (${witnesses.error}).`);
  if (Array.isArray(witnesses.rows) && witnesses.rows.some(v => v.fingerprint === nodeFp)) return { id: 'key', ok: false, state: 'taken', detail: 'This node key is already a witness’s key. Each witness needs its own node key.' };
  if (!Array.isArray(witnesses.rows) || witnesses.truncated !== false) return unknown('the network listed only part of the witnesses.');
  return { id: 'key', ok: true, state: 'free', detail: 'This node key is not a witness’s key yet.' };
}
// The one-line request code the node signs from (decision
// docs/plans/decisions/2026-10-14-consent-request-code.md, BUGS W-22):
// `nodus-consent-v1:<role>:<owner>:<expiry>:<chain>` — role `witness` (a
// stake) or `storage` (a storage registration), owner this wallet's
// fingerprint (128 lowercase hex), expiry the block the consent lasts until
// (decimal), chain the 32-byte id of the chain this page talks to (64
// lowercase hex). No space and no shell character: it is pasted as the one
// argument of `sudo nodus-cli consent <code>`, which finds the node's own key
// in the node's configuration (no -i to get wrong), shows what it is about to
// sign and the node's fingerprint, and asks before it signs. Anything else
// throws: the page never shows a code it did not check.
const CONSENT_ROLES = Object.freeze({ stake: 'witness', storageRegister: 'storage' });
const HEX128 = /^[0-9a-f]{128}$/, HEX64 = /^[0-9a-f]{64}$/;
export function consentRequestCode({ kind, owner, expiry, chainId } = {}) {
  const role = Object.hasOwn(CONSENT_ROLES, kind) ? CONSENT_ROLES[kind] : null;
  if (!role) throw new Error('Unknown consent action.');
  if (typeof owner !== 'string' || !HEX128.test(owner)) throw new Error('Invalid owner for the consent request.');
  let h = null;
  if (typeof expiry === 'bigint') h = expiry > 0n ? expiry.toString() : null;
  else if (typeof expiry === 'string' && /^[1-9]\d{0,19}$/.test(expiry)) h = expiry;
  if (h === null) throw new Error('Invalid expiry block for the consent request.');
  if (typeof chainId !== 'string' || !HEX64.test(chainId)) throw new Error('Invalid chain for the consent request.');
  return `nodus-consent-v1:${role}:${owner}:${h}:${chainId}`;
}
// The command the node owner runs, the code as its one argument.
export function consentRequestCommand(code) {
  return `sudo nodus-cli consent ${code}`;
}
// The first epoch start (a multiple of E) at or after block h.
export function epochStartAtOrAfter(h, E) { return ((h + E - 1n) / E) * E; }
// The timing facts of the design ("Timing facts for the Review screens"),
// as the EARLIEST heights: the transaction included in block tip + 1.
// STAKE: a candidate for an epoch start only DNAC_MIN_TENURE_BLOCKS after
// its stake height -> "joins at the first epoch start at or after block N".
export function witnessJoinFrom(tip, minTenureBlocks) {
  if (typeof tip !== 'bigint' || typeof minTenureBlocks !== 'bigint' || tip <= 0n) return null;
  return tip + 1n + minTenureBlocks;
}
// STORAGE_EXIT included at x: released at B_rel = E * ceil(x / E) as one
// coin locked until B_rel + lockEpochs * E; the node may register again only
// when floor((h-1)/E) - floor((x-1)/E) >= 2, i.e. from B_rel + E + 1.
export function storageExitHeights(tip, E, lockEpochs) {
  if (typeof tip !== 'bigint' || typeof E !== 'bigint' || tip <= 0n || E <= 0n) return null;
  const release = epochStartAtOrAfter(tip + 1n, E);
  return { release, lockedUntil: typeof lockEpochs === 'bigint' ? release + lockEpochs * E : null, registerAgainFrom: release + E + 1n };
}

// ── the page ────────────────────────────────────────────────────────────

const ACTIVITY_TITLES = Object.freeze({ stake: 'Witness bond', storageRegister: 'Storage node bond', storageExit: 'Leaving storage', unstake: 'Leaving the witnesses' });

// Host hooks (src/app.js nodusReady): lockedInputs() — coins of pending
// NODUS transactions; roleRecorder(transfer, title) — the Activity record of
// one prepared transaction ({ broadcast(details), settled(ok) }, src/app.js
// recordRoleActivity).
let panel = null, root = null, client = null, lockedInputs = () => new Set(), roleRecorder = null;
let screen = 'home';
// facts: what this page read from the node — { generation, tip, spendable,
// expiryHeight, bonds, bondsError } (BigInt; spendable null when the balance
// read failed; expiryHeight the last block a transaction built now could be
// included in, null when not computable; bonds { stakeMin, storageBond } —
// the chain's parameters 19 / 21 as the node reports them (BUGS W-20) — or
// null with bondsError) or { error }; null while reading. witnesses /
// storage: the lists the screens need, { rows, truncated, error } (null
// while reading or not asked).
let facts = null, witnesses = null, storage = null, readSeq = 0;
let form = freshForm();
let fieldCount = 0;

function freshForm() {
  // kind: the consent kind of the screen ('stake' | 'storageRegister');
  // reviewKind: the kind of the prepared transaction (the "My registered
  // nodes" screen prepares 'unstake' or 'storageExit');
  // exitNode / stopWitness: the storage node / witness the prepared leave
  // names; error / errorFor: the last failure and the kind it belongs to.
  return { kind: null, reviewKind: null, consent: '', check: null, checkError: '', bond: '', commission: '', exitNode: '', stopWitness: '', expiry: null, prepared: null, busy: false, status: '', error: '', errorFor: null };
}

function el(tag, { className, text } = {}, ...children) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  for (const child of children) if (child) node.append(child);
  return node;
}
function btn(label, onClick, className = 'secondary small') {
  const node = el('button', { className, text: label });
  node.type = 'button';
  node.onclick = onClick;
  return node;
}
const groupDigits = text => { const [whole, fraction] = text.split('.'); return whole.replace(/\B(?=(\d{3})+(?!\d))/g, ',') + (fraction ? `.${fraction}` : ''); };
const nodus = units => `${groupDigits(formatUnits(units, NODUS_ASSET.decimals))} ${NODUS_ASSET.symbol}`;
const block = h => groupDigits(h.toString());

function rules() { try { return client ? parseHf6Rules(client.hf6Rules) : null; } catch { return null; } }
function stakingRules() { try { return client?.stakeable ? parseStakingRules(client.stakingRules) : null; } catch { return null; } }
const epochLength = () => stakingRules()?.epochLength ?? null;
function open() { const r = rules(); return !!r && !!facts && !facts.error && gateOpen(facts.generation, r.generation); }

// Re-reading the node's facts (generation, tip, spendable) — and the list
// the current screen needs. A read started for an older screen or client is
// dropped.
async function readFacts() {
  const seq = ++readSeq, c = client, from = c?.fingerprint;
  facts = null; render();
  if (!c) return;
  let next;
  try {
    const ri = parseRulesetInfo(await c.rulesetInfo());
    let spendable = null;
    try { spendable = parseBalance(await c.balance()).spendable; } catch { spendable = null; }
    // the bonds in force — what the screens show and Review asks for; when
    // they cannot be read the amounts are "unknown" and becoming a witness
    // or a storage node is not offered (fail closed)
    let bonds = null, bondsError = '';
    try { bonds = await hf6Bonds({ client: c, from }); } catch (error) { bondsError = error.message; }
    let expiryHeight = null;
    try { expiryHeight = expiryHeightFor(ri.tip, ri); } catch { expiryHeight = null; }
    next = { generation: ri.generation, tip: ri.tip, spendable, expiryHeight, bonds, bondsError };
  } catch (error) { next = { error: error.message }; }
  if (seq !== readSeq || c !== client) return;
  facts = next;
  const r = rules();
  if (form.kind && !facts.error && r) form.expiry = suggestExpiry(facts.tip, r.consentWindow);
  // the witness bond field starts at the minimum once it is known
  if (form.kind === 'stake' && form.bond === '' && facts.bonds) form.bond = formatUnits(facts.bonds.stakeMin, NODUS_ASSET.decimals);
  if (form.consent) runCheck();
  render();
  const lists = SCREEN_LISTS[screen];
  if (lists?.witnesses) await readWitnesses(seq, c);
  if (lists?.storage) await readStorage(seq, c, from);
}
async function readWitnesses(seq, c) {
  if (!c.stakeable) { witnesses = { rows: [], truncated: true, error: 'The witness list is not available in this wallet version.' }; if (form.consent) runCheck(); render(); return; }
  try {
    const { truncated, validators } = parseValidators(await c.validators());
    if (seq !== readSeq || c !== client) return;
    witnesses = { rows: validators, truncated, error: '' };
  } catch (error) {
    if (seq !== readSeq || c !== client) return;
    witnesses = { rows: [], truncated: true, error: error.message };
  }
  if (form.consent) runCheck();
  render();
}
async function readStorage(seq, c, from) {
  try {
    const list = await storageNodes({ client: c, from });
    if (seq !== readSeq || c !== client) return;
    storage = { ...list, error: '' };
  } catch (error) {
    if (seq !== readSeq || c !== client) return;
    storage = { nodes: [], hidden: 0n, error: error.message };
  }
  render();
}

// The consent checks of the module for what is pasted now, plus the page's
// own two (BUGS W-21): the consent lasts until the transaction's last
// valid block (consentMarginLine), and — for a stake — the one check the
// module leaves to the chain (design §2 item 7): the node key is not
// already a witness's key (keyCheckLine; while the witness list is read,
// failed or partial it is "could not be checked" and Review stays off).
function runCheck() {
  form.check = null; form.checkError = '';
  if (!client || !form.consent.trim() || !form.kind) return;
  if (!facts || facts.error) { form.checkError = 'Waiting for the network’s current block height before the consent can be checked.'; return; }
  try {
    const check = checkConsent({ client, from: client.fingerprint, kind: form.kind, text: form.consent, tip: facts.tip });
    if (check.expiry !== null) check.checks.push(consentMarginLine(check.expiry, facts.expiryHeight));
    if (check.nodeFp && form.kind === 'stake') check.checks.push(keyCheckLine(witnesses, check.nodeFp));
    check.ok = check.checks.every(line => line.ok);
    form.check = check;
  } catch (error) { form.checkError = error.message; }
}

function goto(next, patch = {}) {
  screen = next;
  form = { ...freshForm(), ...patch };
  witnesses = null; storage = null;
  void readFacts();
}

// The fields keep their value and focus across a render (the whole panel is
// drawn again): the focused field is found again by its data-field.
function render() {
  if (!root) return;
  const focused = document.activeElement && root.contains(document.activeElement) && document.activeElement.dataset.field
    ? { field: document.activeElement.dataset.field, start: document.activeElement.selectionStart ?? null, end: document.activeElement.selectionEnd ?? null } : null;
  fieldCount = 0;
  root.replaceChildren(...view());
  if (focused) {
    const node = root.querySelector(`[data-field="${focused.field}"]`);
    if (node) {
      node.focus({ preventScroll: true });
      if (focused.start !== null && focused.end !== null && typeof node.setSelectionRange === 'function') node.setSelectionRange(Math.min(focused.start, node.value.length), Math.min(focused.end, node.value.length));
    }
  }
}

function view() {
  if (!client) return [el('p', { className: 'hint', text: 'Connecting to the Nodus network… This page opens once your wallet is connected.' })];
  if (!client.hf6able || !rules()) return [el('p', { className: 'hint', text: 'Witness and storage roles are not available in this wallet version.' })];
  if (screen === 'home') return homeView();
  const out = [btn('← Nodus', () => goto('home'), 'secondary small roles-back')];
  out.push(...gateNotes());
  if (screen === 'witness') out.push(...consentFlow('stake'));
  else if (screen === 'storage') out.push(...consentFlow('storageRegister'));
  else if (screen === 'nodes') out.push(...witnessesView(), ...storageList());
  if (form.status) out.push(el('p', { className: 'roles-status', text: form.status }));
  return out;
}

// The amber note (design §3) and what the node said.
function gateNotes() {
  const out = [];
  if (!facts) out.push(el('p', { className: 'hint', text: 'Reading the network’s rules…' }));
  else if (facts.error) out.push(el('p', { className: 'roles-amber', text: `${HF6_NOT_YET_TEXT} (The network’s rules could not be read: ${facts.error})` }), btn('Read again', () => void readFacts()));
  else if (!open()) out.push(el('p', { className: 'roles-amber', text: HF6_NOT_YET_TEXT }));
  if (facts && !facts.error && !facts.bonds) {
    const note = el('p', { className: 'roles-amber', text: `The bond amounts are unknown: they could not be read from the network (${facts.bondsError}). Becoming a witness or a storage node stays off until they are read.` });
    note.dataset.note = 'bonds-unknown';
    out.push(note, btn('Read again', () => void readFacts()));
  }
  return out;
}
// The bonds in force as this page last read them (null: reading, or unknown).
const bondsNow = () => (facts && !facts.error ? facts.bonds : null);
const bondsMissingText = () => (facts ? 'The bond amounts are unknown: they could not be read from the network.' : 'Reading the bond amounts…');

function homeView() {
  const b = bondsNow();
  const row = (title, note, onClick, id) => {
    const node = el('button', { className: 'roles-row' }, el('span', { className: 'roles-row-text' }, el('strong', { text: title }), el('small', { text: note })), el('span', { className: 'roles-chevron', text: '›' }));
    node.type = 'button'; node.onclick = onClick; node.dataset.role = id;
    return node;
  };
  return [
    el('p', { className: 'hint', text: 'Take part in running the Nodus network with a node you control. This wallet owns the node, pays the bond and receives the rewards; the node itself only gives its consent.' }),
    ...gateNotes(),
    el('div', { className: 'roles-list' },
      row('Become a witness', `Run a witness node you control. ${b ? `Bond at least ${nodus(b.stakeMin)}.` : bondsMissingText()}`, () => goto('witness', { kind: 'stake', bond: b ? formatUnits(b.stakeMin, NODUS_ASSET.decimals) : '' }), 'witness'),
      row('Become a storage node', `Keep a copy of the chain’s archive. ${b ? `Bond ${nodus(b.storageBond)}.` : bondsMissingText()}`, () => goto('storage', { kind: 'storageRegister' }), 'storage'),
      row('My registered nodes', 'See the witness and storage nodes this wallet owns; stop a witness or leave storage and get the bond back. Fee only.', () => goto('nodes'), 'nodes'))
  ];
}

function card(step, ...children) {
  return el('div', { className: 'roles-card' }, step ? el('p', { className: 'roles-step', text: step }) : null, ...children);
}
function field(labelText, input, name) {
  const id = `roles-f-${++fieldCount}`;
  input.id = id; input.dataset.field = name;
  const label = el('label', { text: labelText });
  label.htmlFor = id;
  return [label, input];
}

// Step 1 (the node command), step 2 (paste + checks), the witness's bond and
// commission, the funds line, Review — or the Review card once prepared.
function consentFlow(kind) {
  if (form.prepared && form.reviewKind === kind) return [reviewCard()];
  if (form.prepared) return [];
  const out = [];
  const owner = client.fingerprint;
  // 1 · the command: one request code (owner, expiry, chain) in one fixed
  // command; the chain is the id this client's module took with the wallet's
  // identity (src/nodus/client.js takeIdentity) — no code without it
  const cmdNodes = [];
  const chainId = client.chainId;
  if (form.expiry === null) cmdNodes.push(el('p', { className: 'hint', text: 'The command appears once the network’s current block height is read.' }));
  else if (typeof chainId !== 'string' || !HEX64.test(chainId)) cmdNodes.push(el('p', { className: 'hint', text: 'The command appears once the network’s chain is read.' }));
  else {
    const command = consentRequestCommand(consentRequestCode({ kind, owner, expiry: form.expiry, chainId }));
    const copyNote = el('span', { className: 'roles-copy-note' });
    cmdNodes.push(
      el('p', { className: 'hint', text: `On the computer that runs your ${kind === 'stake' ? 'witness' : 'storage'} node, run this command. It shows what it is about to sign and your node’s fingerprint, asks you to confirm, and then prints a consent for this wallet, valid until block ${block(form.expiry)}. Paste that consent below.` }),
      el('code', { className: 'roles-cmd', text: command }),
      el('div', { className: 'roles-actions' }, btn('Copy command', async () => {
        try { await navigator.clipboard.writeText(command); copyNote.textContent = 'Copied.'; } catch { copyNote.textContent = 'Copy is unavailable here; select the command and copy it.'; }
      }), copyNote),
      el('p', { className: 'hint', text: 'If the node says the command is unknown, update the node’s software.' }),
      el('p', { className: 'hint', text: 'On the Review, the node key fingerprint must match the node fingerprint this command printed on your node before it signed.' }));
  }
  out.push(card('1 · Prepare your node', ...cmdNodes));
  // 2 · paste and checks
  const area = el('textarea', { className: 'roles-paste' });
  area.rows = 6; area.spellcheck = false; area.autocomplete = 'off';
  area.placeholder = 'nodus-valbind-consent v1\n…';
  area.value = form.consent;
  area.oninput = () => { form.consent = area.value; form.error = ''; form.errorFor = null; runCheck(); render(); };
  const lines = [];
  if (form.checkError) lines.push(el('li', {}, el('span', { className: 'roles-bad', text: '✗' }), el('span', { text: form.checkError })));
  for (const line of form.check?.checks || []) {
    const item = el('li', {}, el('span', { className: line.ok ? 'roles-ok' : 'roles-bad', text: line.ok ? '✓' : '✗' }), el('span', { text: line.detail }));
    item.dataset.check = line.id; item.dataset.ok = String(line.ok);
    lines.push(item);
  }
  const checkNodes = [...field('Paste the consent the node printed', area, 'consent'), el('ul', { className: 'roles-checks' }, ...lines)];
  if (form.check?.nodeFp) checkNodes.push(el('p', { className: 'hint', text: 'Node key fingerprint in this consent:' }), el('code', { className: 'roles-fp-inline', text: form.check.nodeFp }));
  out.push(card('2 · Paste the consent', ...checkNodes));
  // 3 · the bond (witness: a floor; storage: exact) and commission — the
  // values the node reports (BUGS W-20); unknown → no Review
  const b = bondsNow();
  let amount = null, amountError = '';
  if (kind === 'stake') {
    const bond = el('input', { className: 'roles-input' });
    bond.inputMode = 'decimal'; bond.autocomplete = 'off'; bond.value = form.bond;
    bond.oninput = () => { form.bond = bond.value; render(); };
    const commission = el('input', { className: 'roles-input' });
    commission.inputMode = 'decimal'; commission.autocomplete = 'off'; commission.placeholder = 'e.g. 10'; commission.value = form.commission;
    commission.oninput = () => { form.commission = commission.value; render(); };
    const s = stakingRules();
    if (!b) amountError = bondsMissingText();
    else try { amount = bondUnits(form.bond, b.stakeMin); } catch (error) { amountError = error.message; }
    let commissionError = '';
    try { percentToBps(form.commission, s?.commissionMaxBps ?? null); } catch (error) { commissionError = error.message; }
    out.push(card('3 · Bond and commission',
      ...field(b ? `Bond (at least ${nodus(b.stakeMin)})` : 'Bond (the minimum is not known)', bond, 'bond'),
      ...field(`Commission, percent${s ? ` (0 to ${Number(s.commissionMaxBps) / 100})` : ''} — your share of the rewards of those who delegate to your witness`, commission, 'commission'),
      amountError ? el('p', { className: 'roles-error', text: amountError }) : null,
      form.commission && commissionError ? el('p', { className: 'roles-error', text: commissionError }) : null));
    if (!form.commission || commissionError) amountError = amountError || commissionError || 'Enter a commission.';
  } else if (kind === 'storageRegister') {
    if (b) {
      amount = b.storageBond;
      out.push(card('3 · Bond', el('p', { className: 'hint', text: `A storage node’s bond is exactly ${nodus(b.storageBond)}. It does not change the reward; it comes back when the node leaves storage.` })));
    } else {
      amountError = bondsMissingText();
      out.push(card('3 · Bond', el('p', { className: 'roles-error', text: amountError })));
    }
  } else amount = 0n;
  // funds: the bond against what is spendable (the fee comes on top)
  const short = amount !== null && facts && !facts.error && facts.spendable !== null && amount > facts.spendable ? amount - facts.spendable : null;
  if (short !== null) out.push(el('p', { className: 'roles-error', text: `Not enough NODUS: the bond is ${nodus(amount)} plus the network fee, and ${nodus(facts.spendable)} is spendable (${nodus(short)} short).` }));
  const ready = open() && form.check?.ok === true && !amountError && short === null && !form.busy;
  const review = btn(form.busy ? 'Preparing…' : 'Review', () => void startReview(kind), 'roles-primary');
  review.disabled = !ready;
  review.dataset.action = 'review';
  out.push(el('div', { className: 'roles-actions' }, review));
  if (form.error && form.errorFor === kind) out.push(el('p', { className: 'roles-error', text: form.error }));
  return out;
}
function bondUnits(text, floor) {
  const value = typeof text === 'string' ? text.trim().replace(/,/g, '') : '';
  if (!/^\d{1,12}(\.\d{1,8})?$/.test(value)) throw new Error('Enter the bond in NODUS (digits, at most 8 decimals).');
  const [whole, fraction = ''] = value.split('.');
  const units = BigInt(whole) * 10n ** BigInt(NODUS_ASSET.decimals) + BigInt(fraction.padEnd(NODUS_ASSET.decimals, '0') || '0');
  if (units < floor) throw new Error(`The witness bond is at least ${nodus(floor)}.`);
  return units;
}

async function startReview(kind, extra = {}) {
  if (form.busy || !client) return;
  const c = client;
  form.busy = true; form.error = ''; form.errorFor = null; form.status = ''; render();
  try {
    const s = stakingRules(), b = bondsNow();
    const params = { client: c, from: c.fingerprint, kind, locked: lockedInputs() };
    if ((kind === 'stake' || kind === 'storageRegister') && !b) throw new Error(bondsMissingText());
    if (kind === 'stake') {
      params.bond = formatUnits(bondUnits(form.bond, b.stakeMin), NODUS_ASSET.decimals);
      params.commissionBps = percentToBps(form.commission, s?.commissionMaxBps ?? null).toString();
    }
    if (kind !== 'storageExit' && kind !== 'unstake') params.consent = form.consent;
    if (kind === 'unstake') params.validatorId = extra.validatorId;
    if (kind === 'storageExit') params.nodeFp = extra.nodeFp;
    const prepared = await prepareHf6(params);
    if (c !== client) { prepared.cancel(); return; }
    form.prepared = prepared; form.reviewKind = kind;
    if (kind === 'storageExit') form.exitNode = extra.nodeFp;
    if (kind === 'unstake') form.stopWitness = extra.validatorId;
  } catch (error) {
    if (c === client) { form.error = error.message; form.errorFor = kind; }
  } finally {
    if (c === client) { form.busy = false; render(); }
  }
}

// The Review: only what the module read back from the signed bytes.
function reviewCard() {
  const t = form.prepared, d = t.decoded, kind = form.reviewKind, E = epochLength(), r = rules();
  const items = [];
  const big = kind === 'storageExit' ? 'Leave storage' : kind === 'unstake' ? 'Stop being a witness' : `Lock ${nodus(d.bond)}`;
  if (kind === 'stake') {
    items.push('as the witness bond of the node below, owned by this wallet.', 'Rewards go to this wallet.');
    const join = witnessJoinFrom(t.tip, r.minTenureBlocks);
    items.push(join !== null ? `The node joins the witnesses at the first epoch start at or after block ${block(join)} — the earliest; later if this transaction is included later.` : 'The node joins the witnesses after the next epoch boundaries.');
    items.push('The bond stays locked while the node is a witness. To take it back later, use “My registered nodes” → Stop being a witness on this page.');
  } else if (kind === 'unstake') {
    // design "Timing facts" (UNSTAKE → bond back); the chain: the exec marks
    // the row RETIRING (rtn_unstake2_exec), the boundary that graduates it
    // releases the bond to the row's owner locked DNAC_VALIDATOR_UNBOND_EPOCHS
    // epochs and returns every delegation to its delegator locked
    // DNAC_UNDELEGATE_LOCK_EPOCHS epochs (nodus_witness_v2_epoch.c
    // v2ep_graduate / v2ep_release_delegations)
    const s = stakingRules();
    const bondLock = lockBlocks(r.validatorUnbondEpochs, E), delegLock = lockBlocks(s?.undelegateLockEpochs ?? null, E);
    const bond = stopWitnessBond(form.stopWitness);
    items.push(`Witness ${d.validatorId} leaves the witnesses at an epoch boundary — usually after one or two boundaries; the network can take longer. No date is promised.`);
    items.push(`${bond !== null ? `Its bond (${nodus(bond)})` : 'Its bond'} comes back to this wallet as one coin, ${bondLock !== null ? `locked for ${block(bondLock)} blocks after the witness leaves` : 'locked for a while after the witness leaves'}.`);
    items.push(`Delegations to this witness are returned to their delegators at the same boundary, each as a coin ${delegLock !== null ? `locked for ${block(delegLock)} blocks` : 'locked for a while'}; delegators do not need to do anything.`);
    items.push('No bond moves now: this transaction pays only the network fee.');
    items.push('This cannot be undone. Becoming a witness again needs a new bond and your node’s consent (Become a witness).');
    // How a node's key changes now: there is no key change (ROTATE removed
    // from HF-6, decision 2026-10-13-kurultay-18-summary.md item 1) — the
    // witness stops and a new one is made from the new node
    items.push('To move a witness to a new key, stop it here and become a witness again from the new node (a new witness ID; delegators delegate again).');
  } else if (kind === 'storageRegister') {
    items.push('as the storage bond of the node below, owned by this wallet.', 'Storage rewards go to this wallet. The bond does not change the reward.', 'Turning the node off later is not leaving: the bond stays locked until you leave storage here.');
  } else {
    const at = E !== null ? storageExitHeights(t.tip, E, r.storageExitLockEpochs) : null;
    items.push(`Node ${d.nodeFp} stops being a storage node; it is no longer paid.`);
    const exitBond = storageBondOf(form.exitNode), theBond = exitBond !== null ? `The ${nodus(exitBond)} bond` : 'The bond';
    items.push(at && at.lockedUntil !== null ? `${theBond} comes back to this wallet as one coin, released at block ${block(at.release)} at the earliest and locked until block ${block(at.lockedUntil)}.` : `${theBond} comes back to this wallet as one coin after the next epoch boundary, locked for a while after that.`);
    items.push(at ? `This node can register again only after two epoch boundaries — from block ${block(at.registerAgainFrom)} at the earliest.` : 'This node can register again only after two epoch boundaries.');
    items.push('Turning the node off is not leaving: the bond stays locked until you leave here.');
  }
  const fpBlock = kind === 'storageExit' || kind === 'unstake' ? null : el('div', { className: 'roles-fp' },
    el('p', { className: 'roles-fp-label', text: 'Node key fingerprint' }),
    el('code', { className: 'roles-fp-value', text: d.nodeFp }),
    el('p', { className: 'roles-fp-note', text: 'Check that this matches the fingerprint your node printed: the node fingerprint the consent command showed on your node before it signed. If it does not, cancel: someone else’s node would get this role.' }));
  const kv = el('dl', { className: 'roles-kv' });
  const pair = (k, v) => kv.append(el('dt', { text: k }), el('dd', { text: v }));
  if (d.bond > 0n) pair('Bond', nodus(d.bond));
  if (kind === 'stake') pair('Commission', `${Number(d.commissionBps) / 100}%`);
  pair('Network fee', nodus(d.fee));
  // the change output read back from the signed bytes (to this wallet;
  // HF-6 Connect red-team round 1, Astra F5)
  pair('Change back to you', nodus(d.change));
  pair('Balance after', nodus(t.balanceAfter));
  if (d.consentExpiry !== null) pair('Consent valid until block', block(d.consentExpiry));
  pair('Valid until block', block(d.expiryHeight));
  // (a consent ending before the transaction's validity never reaches this
  // card: the page's check and prepareHf6 refuse it — BUGS W-21)
  const cancel = btn('Cancel', () => { t.cancel(); form.prepared = null; form.reviewKind = null; render(); });
  const confirm = btn(kind === 'storageExit' ? 'Leave storage' : kind === 'unstake' ? 'Stop being a witness' : 'Confirm and send', () => void confirmPrepared(), 'roles-primary');
  confirm.dataset.action = 'confirm';
  confirm.disabled = form.busy || !open() || !roleRecorder;
  return el('div', { className: 'roles-card roles-review' },
    el('p', { className: 'roles-step', text: 'You are about to' }),
    el('p', { className: 'roles-big', text: big }),
    el('ul', { className: 'roles-sum' }, ...items.map(text => el('li', { text }))),
    fpBlock, kv,
    roleRecorder ? null : el('p', { className: 'roles-error', text: 'Activity is not available, so nothing can be sent from here.' }),
    el('div', { className: 'roles-actions' }, cancel, confirm),
    form.error && form.errorFor === kind ? el('p', { className: 'roles-error', text: form.error }) : null);
}
// The leaving storage node's bond as the node's list gives it (the bond it
// registered with — not today's STORAGE_BOND); null when the list does not
// have the row.
function storageBondOf(fp) { return storage?.nodes?.find(n => n.fp === fp)?.bond ?? null; }
// The witness's bond as the node's list gives it (one node's answer, like
// the storage bond above); null when the list does not have the row.
function stopWitnessBond(vid) { return witnesses?.rows?.find(v => v.validatorId === vid)?.selfStake ?? null; }

async function confirmPrepared() {
  const t = form.prepared, kind = form.reviewKind, c = client;
  if (!t || form.busy || !roleRecorder || !open()) return;
  const record = roleRecorder(t, ACTIVITY_TITLES[kind]);
  form.busy = true; form.error = ''; form.errorFor = null; render();
  try {
    const hash = await t.confirm(details => record.broadcast(details));
    record.settled(true);
    if (c !== client) return;
    const done = `${ACTIVITY_TITLES[kind]} submitted; confirmation is pending. Transaction ID ${hash}. Its status is tracked in Activity.`;
    goto(screen, { kind: screen === 'witness' ? 'stake' : screen === 'storage' ? 'storageRegister' : null, status: done, bond: screen === 'witness' && bondsNow() ? formatUnits(bondsNow().stakeMin, NODUS_ASSET.decimals) : '' });
  } catch (error) {
    record.settled(false);
    if (c !== client) return;
    form.busy = false; form.prepared = null; form.reviewKind = null;
    form.error = error.message; form.errorFor = kind;
    render();
  }
}

// "Your storage nodes" (on "My registered nodes"): this wallet's storage
// nodes, each active one with Leave. While the witnesses card's Review is
// open this card is not shown (as consentFlow hides behind another kind's
// Review): one prepared transaction at a time.
function storageList() {
  if (form.prepared && form.reviewKind !== 'storageExit') return [];
  const out = [];
  const head = el('p', { className: 'roles-step', text: 'Your storage nodes' });
  if (!storage) return [card(null, head, el('p', { className: 'hint', text: 'Reading your storage nodes…' }))];
  if (storage.error) return [card(null, head, el('p', { className: 'hint', text: `Your storage nodes could not be read: ${storage.error}` }))];
  if (form.prepared && form.reviewKind === 'storageExit') return [card(null, head), reviewCard()];
  const rows = storage.nodes.map(n => {
    const main = el('span', { className: 'stake-main' }, el('strong', { text: `Node ${shortKey(n.fp)}` }), el('small', { text: `${n.statusText} · bond ${nodus(n.bond)} · since block ${block(n.registered)}${n.exit > 0n ? ` · left at block ${block(n.exit)}` : ''}` }));
    main.title = n.fp;
    const row = el('div', { className: 'stake-row roles-node' }, main);
    row.dataset.node = n.fp;
    if (n.status === 'active') {
      const leave = btn(form.busy ? 'Preparing…' : 'Leave', () => void startReview('storageExit', { nodeFp: n.fp }));
      leave.disabled = form.busy || !open();
      leave.dataset.action = 'leave';
      row.append(el('span', { className: 'stake-actions' }, leave));
    }
    return row;
  });
  out.push(card(null, head,
    rows.length ? el('div', { className: 'stake-list' }, ...rows) : el('p', { className: 'hint', text: 'This wallet has no storage node.' }),
    storage.hidden > 0n ? el('p', { className: 'hint', text: `${storage.hidden} more ${storage.hidden === 1n ? 'node is' : 'nodes are'} not shown (the network lists ${storage.nodes.length} at most).` }) : null,
    form.error && form.errorFor === 'storageExit' ? el('p', { className: 'roles-error', text: form.error }) : null));
  return out;
}

// "Your witnesses" (on "My registered nodes"): this wallet's generation-4
// witnesses, each active / eligible one with "Stop being a witness"
// (generation-4 UNSTAKE, fee only; the adapter re-checks owner and status
// before anything is built). While the storage card's Review is open this
// card is not shown, like storageList above.
function witnessesView() {
  if (form.prepared && form.reviewKind !== 'unstake') return [];
  const head = el('p', { className: 'roles-step', text: 'Your witnesses' });
  if (!witnesses) return [card(null, head, el('p', { className: 'hint', text: 'Reading your witnesses…' }))];
  if (witnesses.error) return [card(null, head, el('p', { className: 'hint', text: `Your witnesses could not be read: ${witnesses.error}` }))];
  if (form.prepared && form.reviewKind === 'unstake') return [card(null, head), reviewCard()];
  const mine = ownWitnesses(witnesses.rows, client.fingerprint);
  const rows = mine.map(v => {
    const main = el('span', { className: 'stake-main' }, el('strong', { text: `Witness ${shortKey(v.validatorId)}` }), el('small', { text: `node ${shortKey(v.fingerprint)} · ${v.statusText} · bond ${nodus(v.selfStake)}` }));
    main.title = v.validatorId;
    const row = el('div', { className: 'stake-row roles-node' }, main);
    row.dataset.witness = v.validatorId;
    if (canStopWitness(v)) {
      const stop = btn(form.busy ? 'Preparing…' : 'Stop being a witness', () => void startReview('unstake', { validatorId: v.validatorId }));
      stop.disabled = form.busy || !open();
      stop.dataset.action = 'unstake';
      row.append(el('span', { className: 'stake-actions' }, stop));
    }
    return row;
  });
  return [card(null, head,
    rows.length ? el('div', { className: 'stake-list' }, ...rows) : el('p', { className: 'hint', text: 'This wallet owns no witness.' }),
    rows.length ? el('p', { className: 'hint', text: 'Only an active witness, or one waiting for a seat, can stop. A witness that is already leaving shows no button.' }) : null,
    form.error && form.errorFor === 'unstake' ? el('p', { className: 'roles-error', text: form.error }) : null)];
}

// ── mount + the wallet extension ────────────────────────────────────────

export function mountNodusRoles({ panelNode, rootNode }) {
  panel = panelNode; root = rootNode;
  // The page is available whenever the wallet is open (its own text says
  // what is missing while the network connects).
  if (panel) panel.hidden = false;
  render();
}
function start(detail) {
  client = detail?.client || null;
  lockedInputs = typeof detail?.lockedInputs === 'function' ? detail.lockedInputs : () => new Set();
  roleRecorder = typeof detail?.roleRecorder === 'function' ? detail.roleRecorder : null;
  screen = 'home'; form = freshForm(); witnesses = null; storage = null;
  void readFacts();
}
function reset() {
  readSeq++;
  form.prepared?.cancel?.();
  client = null; lockedInputs = () => new Set(); roleRecorder = null;
  screen = 'home'; form = freshForm(); facts = null; witnesses = null; storage = null;
  render();
}
export const nodusRolesExtension = {
  nodusReady(detail) { start(detail); },
  nodusClosing() { reset(); },
  nodusUnavailable() { reset(); },
  vaultDeleting() { reset(); },
  locked() { reset(); }
};
