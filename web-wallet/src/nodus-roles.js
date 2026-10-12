// Nodus Connect — the "Nodus" page (#nodus-roles; More → Nodus): become a
// witness, become a storage node, change your node's key, and leave
// storage. src/app.js wallet pages show the page; this module fills its
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
// - Times are BLOCK HEIGHTS computed from the chain constants the module
//   carries (epoch length, minimum tenure, storage exit lock) — earliest
//   heights only, never hours or days; without a constant, no number.
// - Every text through textContent; no innerHTML. Nothing is stored on the
//   device (decision 2026-10-02-device-cache-only-when-saved: the page keeps
//   its state in memory and clears it on lock).
import { formatUnits } from './core.js';
import { NODUS_ASSET } from './nodus/network.js';
import {
  HF6_NOT_YET_TEXT, parseHf6Rules, parseRulesetInfo, parseBalance, parseValidators, parseStakingRules,
  checkConsent, storageNodes, prepareHf6, shortKey
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
// The Review warning (nodus-cli.c cmd_v2_stake's): the consent expires
// before the transaction's own validity ends — included after the consent's
// block, the network refuses it.
export function consentExpiresEarly(consentExpiry, expiryHeight) {
  return typeof consentExpiry === 'bigint' && typeof expiryHeight === 'bigint' && consentExpiry < expiryHeight;
}
// The command the node runs (nodus/tools/nodus-cli.c usage: `validator
// consent --op stake|rotate --owner <hex128> [--subject <validator_id>]
// --expiry <h>`, `storage consent --owner <hex128> --expiry <h>`; -i the
// node identity, -s the node it asks for the chain id and tip).
export function consentCommand({ kind, owner, expiry, validatorId = '' }) {
  const head = 'nodus-cli -i ~/.nodus -s 127.0.0.1';
  if (kind === 'storageRegister') return `${head} storage consent --owner ${owner} --expiry ${expiry}`;
  if (kind === 'rotate') return `${head} validator consent --op rotate --owner ${owner} --subject ${validatorId} --expiry ${expiry}`;
  return `${head} validator consent --op stake --owner ${owner} --expiry ${expiry}`;
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
// ROTATE: accepted (or deferred) at the first boundary F >= the commit
// height; the switch U = F + E (the new node signs from U + 2); the old key
// is released at U + E; the old node stays up through U + 1 (through
// U + floor(E/2) if it is also a storage node).
export function rotationHeights(tip, E) {
  if (typeof tip !== 'bigint' || typeof E !== 'bigint' || tip <= 0n || E <= 0n) return null;
  const F = epochStartAtOrAfter(tip + 1n, E), U = F + E;
  return { boundary: F, switchAt: U, keepThrough: U + 1n, keepThroughStorage: U + E / 2n, releasedAt: U + E };
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

const TITLES = Object.freeze({ stake: 'Become a witness', storageRegister: 'Become a storage node', rotate: 'Change your node’s key', storageExit: 'Leave storage' });
const ACTIVITY_TITLES = Object.freeze({ stake: 'Witness bond', storageRegister: 'Storage node bond', rotate: 'Node key change', storageExit: 'Leaving storage' });
const WHOAMI = 'nodus-cli -i ~/.nodus whoami';

// Host hooks (src/app.js nodusReady): lockedInputs() — coins of pending
// NODUS transactions; roleRecorder(transfer, title) — the Activity record of
// one prepared transaction ({ broadcast(details), settled(ok) }, src/app.js
// recordRoleActivity).
let panel = null, root = null, client = null, lockedInputs = () => new Set(), roleRecorder = null;
let screen = 'home';
// facts: what this page read from the node — { generation, tip, spendable }
// (BigInt; spendable null when the balance read failed) or { error }; null
// while reading. witnesses / storage: the lists the screens need, { rows,
// error } (null while reading or not asked).
let facts = null, witnesses = null, storage = null, readSeq = 0;
let form = freshForm();
let fieldCount = 0;

function freshForm() {
  // kind: the consent kind of the screen ('stake' | 'storageRegister' |
  // 'rotate'); reviewKind: the kind of the prepared transaction (a storage
  // screen also prepares 'storageExit'); error / errorFor: the last failure
  // and the kind it belongs to.
  return { kind: null, reviewKind: null, consent: '', check: null, checkError: '', bond: '', commission: '', witness: '', exitNode: '', expiry: null, prepared: null, busy: false, status: '', error: '', errorFor: null };
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
    next = { generation: ri.generation, tip: ri.tip, spendable };
  } catch (error) { next = { error: error.message }; }
  if (seq !== readSeq || c !== client) return;
  facts = next;
  const r = rules();
  if (form.kind && !facts.error && r) form.expiry = suggestExpiry(facts.tip, r.consentWindow);
  if (form.consent) runCheck();
  render();
  if (screen === 'rotate' || screen === 'witness') await readWitnesses(seq, c);
  if (screen === 'storage') await readStorage(seq, c, from);
}
async function readWitnesses(seq, c) {
  if (!c.stakeable) { witnesses = { rows: [], error: 'The witness list is not available in this wallet version.' }; render(); return; }
  try {
    const { validators } = parseValidators(await c.validators());
    if (seq !== readSeq || c !== client) return;
    witnesses = { rows: validators, error: '' };
  } catch (error) {
    if (seq !== readSeq || c !== client) return;
    witnesses = { rows: [], error: error.message };
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

// The consent checks of the module for what is pasted now, plus the one
// check the module leaves to the chain (design §2 item 7) where the witness
// list was read: a stake's node key is not already a witness's key; a
// rotate's new key differs from the witness's current one.
function runCheck() {
  form.check = null; form.checkError = '';
  if (!client || !form.consent.trim() || !form.kind) return;
  if (!facts || facts.error) { form.checkError = 'Waiting for the network’s current block height before the consent can be checked.'; return; }
  if (form.kind === 'rotate' && !form.witness) { form.checkError = 'Choose the witness first.'; return; }
  try {
    const check = checkConsent({ client, from: client.fingerprint, kind: form.kind, text: form.consent, validatorId: form.witness, tip: facts.tip });
    const rows = witnesses && !witnesses.error ? witnesses.rows : null;
    if (rows && check.nodeFp) {
      if (form.kind === 'stake') {
        const taken = rows.some(v => v.fingerprint === check.nodeFp);
        check.checks.push({ id: 'key', ok: !taken, detail: taken ? 'This node key is already a witness’s key. Each witness needs its own node key.' : 'This node key is not a witness’s key yet.' });
      } else if (form.kind === 'rotate') {
        const current = rows.find(v => v.validatorId === form.witness);
        const same = !!current && current.fingerprint === check.nodeFp;
        check.checks.push({ id: 'key', ok: !same, detail: same ? 'This is the witness’s current node key. Run the command on the NEW node.' : 'The new node key differs from the witness’s current one.' });
      }
      check.ok = check.checks.every(line => line.ok);
    }
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
  else if (screen === 'storage') out.push(...storageList(), ...consentFlow('storageRegister'));
  else if (screen === 'rotate') out.push(...rotateView());
  if (form.status) out.push(el('p', { className: 'roles-status', text: form.status }));
  return out;
}

// The amber note (design §3) and what the node said.
function gateNotes() {
  const out = [];
  if (!facts) out.push(el('p', { className: 'hint', text: 'Reading the network’s rules…' }));
  else if (facts.error) out.push(el('p', { className: 'roles-amber', text: `${HF6_NOT_YET_TEXT} (The network’s rules could not be read: ${facts.error})` }), btn('Read again', () => void readFacts()));
  else if (!open()) out.push(el('p', { className: 'roles-amber', text: HF6_NOT_YET_TEXT }));
  return out;
}

function homeView() {
  const r = rules();
  const row = (title, note, onClick, id) => {
    const node = el('button', { className: 'roles-row' }, el('span', { className: 'roles-row-text' }, el('strong', { text: title }), el('small', { text: note })), el('span', { className: 'roles-chevron', text: '›' }));
    node.type = 'button'; node.onclick = onClick; node.dataset.role = id;
    return node;
  };
  return [
    el('p', { className: 'hint', text: 'Take part in running the Nodus network with a node you control. This wallet owns the node, pays the bond and receives the rewards; the node itself only gives its consent.' }),
    ...gateNotes(),
    el('div', { className: 'roles-list' },
      row('Become a witness', `Run a witness node you control. Bond at least ${nodus(r.stakeMin)}.`, () => goto('witness', { kind: 'stake', bond: formatUnits(r.stakeMin, NODUS_ASSET.decimals) }), 'witness'),
      row('Become a storage node', `Keep a copy of the chain’s archive. Bond ${nodus(r.storageBond)}.`, () => goto('storage', { kind: 'storageRegister' }), 'storage'),
      row('Change your node’s key', 'Move your witness to a new machine or key. Fee only.', () => goto('rotate', { kind: 'rotate' }), 'rotate'))
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
  const r = rules();
  const out = [];
  const owner = client.fingerprint;
  // 1 · the command
  const cmdNodes = [];
  if (kind === 'rotate' && !form.witness) cmdNodes.push(el('p', { className: 'hint', text: 'Choose the witness first.' }));
  else if (form.expiry === null) cmdNodes.push(el('p', { className: 'hint', text: 'The command appears once the network’s current block height is read.' }));
  else {
    const command = consentCommand({ kind, owner, expiry: form.expiry.toString(), validatorId: form.witness });
    const copyNote = el('span', { className: 'roles-copy-note' });
    cmdNodes.push(
      el('p', { className: 'hint', text: kind === 'rotate'
        ? `On the NEW node (the computer and key the witness moves to), run this. It prints a consent for this wallet, valid until block ${block(form.expiry)}.`
        : `On the computer that runs your ${kind === 'stake' ? 'witness' : 'storage'} node, run this. It prints a consent for this wallet, valid until block ${block(form.expiry)}.` }),
      el('code', { className: 'roles-cmd', text: command }),
      el('div', { className: 'roles-actions' }, btn('Copy command', async () => {
        try { await navigator.clipboard.writeText(command); copyNote.textContent = 'Copied.'; } catch { copyNote.textContent = 'Copy is unavailable here; select the command and copy it.'; }
      }), copyNote),
      el('p', { className: 'hint', text: `Your node’s key fingerprint, to compare on the Review: ${WHOAMI}` }));
  }
  out.push(card(kind === 'rotate' ? '2 · On the new node, run' : '1 · Prepare your node', ...cmdNodes));
  if (kind === 'rotate' && !form.witness) return out;
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
  out.push(card(kind === 'rotate' ? '3 · Paste the consent' : '2 · Paste the consent', ...checkNodes));
  // 3 · the bond (witness: a floor; storage: exact) and commission
  let amount = null, amountError = '';
  if (kind === 'stake') {
    const bond = el('input', { className: 'roles-input' });
    bond.inputMode = 'decimal'; bond.autocomplete = 'off'; bond.value = form.bond;
    bond.oninput = () => { form.bond = bond.value; render(); };
    const commission = el('input', { className: 'roles-input' });
    commission.inputMode = 'decimal'; commission.autocomplete = 'off'; commission.placeholder = 'e.g. 10'; commission.value = form.commission;
    commission.oninput = () => { form.commission = commission.value; render(); };
    const s = stakingRules();
    try { amount = bondUnits(form.bond, r.stakeMin); } catch (error) { amountError = error.message; }
    let commissionError = '';
    try { percentToBps(form.commission, s?.commissionMaxBps ?? null); } catch (error) { commissionError = error.message; }
    out.push(card('3 · Bond and commission',
      ...field(`Bond (at least ${nodus(r.stakeMin)})`, bond, 'bond'),
      ...field(`Commission, percent${s ? ` (0 to ${Number(s.commissionMaxBps) / 100})` : ''} — your share of the rewards of those who delegate to your witness`, commission, 'commission'),
      amountError ? el('p', { className: 'roles-error', text: amountError }) : null,
      form.commission && commissionError ? el('p', { className: 'roles-error', text: commissionError }) : null));
    if (!form.commission || commissionError) amountError = amountError || commissionError || 'Enter a commission.';
  } else if (kind === 'storageRegister') {
    amount = r.storageBond;
    out.push(card('3 · Bond', el('p', { className: 'hint', text: `A storage node’s bond is exactly ${nodus(r.storageBond)}. It does not change the reward; it comes back when the node leaves storage.` })));
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
    const r = rules(), s = stakingRules();
    const params = { client: c, from: c.fingerprint, kind, locked: lockedInputs() };
    if (kind !== 'storageExit') params.consent = form.consent;
    if (kind === 'stake') {
      params.bond = formatUnits(bondUnits(form.bond, r.stakeMin), NODUS_ASSET.decimals);
      params.commissionBps = percentToBps(form.commission, s?.commissionMaxBps ?? null).toString();
    }
    if (kind === 'rotate') params.validatorId = form.witness;
    if (kind === 'storageExit') params.nodeFp = extra.nodeFp;
    const prepared = await prepareHf6(params);
    if (c !== client) { prepared.cancel(); return; }
    form.prepared = prepared; form.reviewKind = kind;
    if (kind === 'storageExit') form.exitNode = extra.nodeFp;
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
  const big = kind === 'rotate' ? 'Change your witness’s node key' : kind === 'storageExit' ? 'Leave storage' : `Lock ${nodus(d.bond)}`;
  if (kind === 'stake') {
    items.push('as the witness bond of the node below, owned by this wallet.', 'Rewards go to this wallet.');
    const join = witnessJoinFrom(t.tip, r.minTenureBlocks);
    items.push(join !== null ? `The node joins the witnesses at the first epoch start at or after block ${block(join)} — the earliest; later if this transaction is included later.` : 'The node joins the witnesses after the next epoch boundaries.');
    items.push('This wallet cannot take the bond back yet: leaving the witnesses is not offered here. The bond stays locked while the node is a witness.');
  } else if (kind === 'storageRegister') {
    items.push('as the storage bond of the node below, owned by this wallet.', 'Storage rewards go to this wallet. The bond does not change the reward.', 'Turning the node off later is not leaving: the bond stays locked until you leave storage here.');
  } else if (kind === 'rotate') {
    const at = E !== null ? rotationHeights(t.tip, E) : null;
    items.push(`Witness ${d.validatorId} moves to the new node below. No bond moves.`);
    items.push(at ? `The switch happens at block ${block(at.switchAt)} at the earliest (after two epoch boundaries). The network can defer a key change to a later boundary; no date is promised.` : 'The switch happens after the next epoch boundaries; the network can defer it to a later boundary.');
    items.push(at ? `Keep the OLD node running at least through block ${block(at.keepThrough)} (through block ${block(at.keepThroughStorage)} if it is also a storage node). Its old key is released at block ${block(at.releasedAt)}.` : 'Keep the OLD node running until the switch has happened.');
  } else {
    const at = E !== null ? storageExitHeights(t.tip, E, r.storageExitLockEpochs) : null;
    items.push(`Node ${d.nodeFp} stops being a storage node; it is no longer paid.`);
    items.push(at && at.lockedUntil !== null ? `The ${nodus(storageBondOf(form.exitNode))} bond comes back to this wallet as one coin, released at block ${block(at.release)} at the earliest and locked until block ${block(at.lockedUntil)}.` : 'The bond comes back to this wallet as one coin after the next epoch boundary, locked for a while after that.');
    items.push(at ? `This node can register again only after two epoch boundaries — from block ${block(at.registerAgainFrom)} at the earliest.` : 'This node can register again only after two epoch boundaries.');
    items.push('Turning the node off is not leaving: the bond stays locked until you leave here.');
  }
  const fpBlock = kind === 'storageExit' ? null : el('div', { className: 'roles-fp' },
    el('p', { className: 'roles-fp-label', text: kind === 'rotate' ? 'NEW node key fingerprint' : 'Node key fingerprint' }),
    el('code', { className: 'roles-fp-value', text: d.nodeFp }),
    el('p', { className: 'roles-fp-note', text: `Check that this matches the fingerprint your node printed (${WHOAMI} on that node). If it does not, cancel: someone else’s node would get this role.` }));
  const kv = el('dl', { className: 'roles-kv' });
  const pair = (k, v) => kv.append(el('dt', { text: k }), el('dd', { text: v }));
  if (d.bond > 0n) pair('Bond', nodus(d.bond));
  if (kind === 'stake') pair('Commission', `${Number(d.commissionBps) / 100}%`);
  pair('Network fee', nodus(d.fee));
  pair('Balance after', nodus(t.balanceAfter));
  if (d.consentExpiry !== null) pair('Consent valid until block', block(d.consentExpiry));
  pair('Valid until block', block(d.expiryHeight));
  const warn = consentExpiresEarly(d.consentExpiry, d.expiryHeight)
    ? el('p', { className: 'roles-amber', text: `This consent expires at block ${block(d.consentExpiry)}, before this transaction’s validity ends (block ${block(d.expiryHeight)}). If the transaction is included after block ${block(d.consentExpiry)}, the network refuses it. Make a new consent on the node if in doubt.` })
    : null;
  if (warn) warn.dataset.warning = 'consent-expiry';
  const cancel = btn('Cancel', () => { t.cancel(); form.prepared = null; form.reviewKind = null; render(); });
  const confirm = btn(kind === 'storageExit' ? 'Leave storage' : 'Confirm and send', () => void confirmPrepared(), 'roles-primary');
  confirm.dataset.action = 'confirm';
  confirm.disabled = form.busy || !open() || !roleRecorder;
  return el('div', { className: 'roles-card roles-review' },
    el('p', { className: 'roles-step', text: 'You are about to' }),
    el('p', { className: 'roles-big', text: big }),
    el('ul', { className: 'roles-sum' }, ...items.map(text => el('li', { text }))),
    fpBlock, kv, warn,
    roleRecorder ? null : el('p', { className: 'roles-error', text: 'Activity is not available, so nothing can be sent from here.' }),
    el('div', { className: 'roles-actions' }, cancel, confirm),
    form.error && form.errorFor === kind ? el('p', { className: 'roles-error', text: form.error }) : null);
}
function storageBondOf(fp) { return storage?.nodes?.find(n => n.fp === fp)?.bond ?? rules().storageBond; }

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
    goto(screen, { kind: screen === 'witness' ? 'stake' : screen === 'storage' ? 'storageRegister' : 'rotate', status: done, bond: screen === 'witness' ? formatUnits(rules().stakeMin, NODUS_ASSET.decimals) : '' });
  } catch (error) {
    record.settled(false);
    if (c !== client) return;
    form.busy = false; form.prepared = null; form.reviewKind = null;
    form.error = error.message; form.errorFor = kind;
    render();
  }
}

function storageList() {
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

function rotateView() {
  const out = [];
  const head = el('p', { className: 'roles-step', text: '1 · Which witness?' });
  if (!witnesses) return [card(null, head, el('p', { className: 'hint', text: 'Reading your witnesses…' }))];
  if (witnesses.error) return [card(null, head, el('p', { className: 'hint', text: `Your witnesses could not be read: ${witnesses.error}` }))];
  const mine = ownWitnesses(witnesses.rows, client.fingerprint);
  if (!mine.length) return [card(null, head, el('p', { className: 'hint', text: 'This wallet owns no witness.' }))];
  const choices = mine.map(v => {
    const input = el('input');
    input.type = 'radio'; input.name = 'roles-witness'; input.value = v.validatorId; input.checked = form.witness === v.validatorId;
    input.dataset.field = `witness-${v.validatorId.slice(0, 16)}`;
    input.disabled = !!form.prepared || form.busy;
    input.onchange = () => { form.witness = v.validatorId; form.consent = ''; form.check = null; form.checkError = ''; form.error = ''; render(); };
    const label = el('label', { className: 'roles-radio' }, input, el('span', {}, el('strong', { text: `Witness ${shortKey(v.validatorId)}` }), el('small', { text: ` · node ${shortKey(v.fingerprint)} · ${v.statusText}` })));
    label.title = v.validatorId;
    label.dataset.witness = v.validatorId;
    return label;
  });
  out.push(card(null, head, ...choices));
  out.push(...consentFlow('rotate'));
  return out;
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
