// Smart contracts — the panel of the wallet's Smart contracts page (#contracts;
// src/app.js wallet pages show the page, this module only fills the panel and
// says whether it is available through the panel's `hidden`).
//
// Design docs/plans/2026-10-04-nodus-evm-chain-integration-design.md rev 3 §16
// (wallet: the real destination, value, fee ceiling and chain are shown and
// signed; the pending transaction; included-and-succeeded vs
// included-and-failed vs refused; tickets and collecting them) and §18.
// Decisions 2026-10-04-nodus-evm-kurultay-k1.md (operator 1, 3, 4) and
// 2026-10-04-nodus-evm-kurultay-k2-summary.md (operator 2: one pending smart-
// contract transaction per account — src/evm/contract.js EvmAccount).
//
// HOST-DRIVEN like the shared vaults: a wallet extension (src/wallet-
// extensions.js) on the wallet's ONE NODUS client. Shown only when the
// loaded module can build smart-contract transactions or read them
// (client.evmBuildable / evmReadable) and NODUS is the selected network —
// both are false on a node that has not voted the EVM generation in
// (src/nodus/client.js asks rulesetInfo at unlock), so there the panel
// stays hidden.
//
// WHAT IS SHOWN IS READ BACK: a review shows the module's decoding of the
// envelope it signed (src/evm/contract.js decodeEvmBuilt), never the form's
// text. Rendering: every text through textContent; no innerHTML.
import { EvmAccount, Contract, describeArgs } from './contract.js';
import { Interface, typeString } from './abi.js';
import { toChecksumAddress } from './address.js';
import { formatRaw, formatWei, parseRaw, parseWei, weiToRaw } from './units.js';
import { NODUS_ASSET } from '../nodus/network.js';
// The session log (src/session-log.js, memory only, scrubbed): the panel's
// failures and its transactions' outcomes.
import { sessionLog } from '../session-log.js';

const HEX128 = /^[0-9a-f]{128}$/;

// Host hooks (src/app.js nodusReady, red-team 1 F8): lockedInputs() — the
// coins of pending NODUS transactions; recordPending(details, { title,
// amount }) — writes and saves this transaction's Activity row BEFORE the
// envelope leaves the browser; pendingRows() — the unresolved rows that may
// be this account's ([{ hash, expiryHeight }]), restored with the Activity.
let client, account, root, panel, lockedInputs = () => new Set(), recordPending = null, pendingRows = () => [];
let generation = 0, busy = false, status = '';
let balance = null;                          // { wei, nonce, height } | null
const tickets = new Map();                   // ticket id -> { amountRaw, dest, pending } | { error }
const recent = [];                           // [{ intentId, title, state, result?, contract? }]
let contract = null;                         // Contract | null
let deployDraft = null;                      // { iface, bytecode, args } | null
let contractError = '';
let fieldCount = 0;                          // label/input ids of this page
const readResults = new Map();               // function signature -> text

const $ = id => document.getElementById(id);
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
function field(labelText, input) {
  const id = `evm-f-${++fieldCount}`;
  input.id = id;
  const label = el('label', { text: labelText });
  label.htmlFor = id;
  return [label, input];
}
function input({ placeholder = '', value = '', mono = false } = {}) {
  const node = el('input');
  node.autocomplete = 'off'; node.spellcheck = false; node.placeholder = placeholder; node.value = value;
  if (mono) node.className = 'evm-mono';
  return node;
}
function area(placeholder) {
  const node = el('textarea');
  node.rows = 4; node.spellcheck = false; node.placeholder = placeholder;
  return node;
}
const nodus = raw => `${formatRaw(raw)} NODUS`;
const short = hex => `${hex.slice(0, 10)}…${hex.slice(-6)}`;

// ── lifecycle (wallet extension events) ─────────────────────────────────

function reset() {
  generation++;
  client = undefined; account = undefined; busy = false; status = ''; balance = null;
  tickets.clear(); recent.length = 0; contract = null; deployDraft = null; contractError = ''; readResults.clear();
  lockedInputs = () => new Set(); recordPending = null; pendingRows = () => [];
  render();
}

function start(detail) {
  reset();
  const c = detail?.client;
  if (!c || !(c.evmBuildable || c.evmReadable)) return;
  client = c;
  if (typeof detail.lockedInputs === 'function') lockedInputs = detail.lockedInputs;
  if (typeof detail.evmRecord === 'function') recordPending = detail.evmRecord;
  if (typeof detail.evmPending === 'function') pendingRows = detail.evmPending;
  account = new EvmAccount({ client: c, fingerprint: c.fingerprint, lockedInputs: () => lockedInputs(), reservations: () => pendingRows() });
  render();
  void refreshBalance();
}

async function act(work) {
  if (busy) return;
  busy = true; status = ''; render();
  const gen = generation;
  try { await work(gen); } catch (error) { if (gen === generation) { status = error?.message || 'Something went wrong.'; sessionLog.log('evm', status, { error: true }); } }
  finally { if (gen === generation) { busy = false; render(); } }
}

async function refreshBalance() {
  if (!account || !client.evmReadable) return;
  const gen = generation;
  try {
    const a = await account.account();
    if (gen === generation) balance = { wei: a.balanceWei, nonce: a.nonce, height: a.height };
  } catch (error) { if (gen === generation) { balance = null; status = error?.message || 'Balance unavailable.'; sessionLog.log('evm', status, { error: true }); } }
  if (gen === generation) render();
}

// ── review dialog ───────────────────────────────────────────────────────

function showReview(view, title, onDone) {
  const dialog = el('dialog', { className: 'evm-review' });
  dialog.setAttribute('aria-label', title);
  const list = el('dl');
  for (const [k, v] of view.review) list.append(el('dt', { text: k }), el('dd', { text: v }));
  const error = el('p'); error.setAttribute('role', 'alert');
  const cancel = btn('Cancel', () => { view.cancel(); dialog.close(); }, 'secondary');
  // The Activity row (and with it the coins' hold and this account's
  // one-pending reservation) is written and saved by the wallet BEFORE the
  // envelope leaves the browser (F8). Coins leaving this wallet: the
  // deposit's amount (DEPOSIT) plus the fee.
  const d = view.decoded;
  const amount = formatRaw((d.op === 'deposit' ? d.amount : 0n) + d.fee);
  const record = recordPending ? details => recordPending(details, { title, amount }) : undefined;
  const confirm = btn('Confirm & send', async () => {
    confirm.disabled = true; cancel.disabled = true;
    try {
      const sent = await view.confirm(record);
      dialog.close();
      onDone(sent);
    } catch (e) {
      // recorded but the submission's outcome is uncertain: tracked like a
      // sent one (its reservation stays until a receipt or the expiry)
      if (e?.sent) { dialog.close(); onDone(e.sent, e.message); return; }
      error.textContent = e?.message || 'Sending failed.';
      cancel.disabled = false;
      cancel.textContent = 'Close';
      cancel.onclick = () => dialog.close();
    }
  }, '');
  dialog.append(el('h2', { text: title }), el('p', { className: 'notice', text: 'Testnet transaction. Check every line; sending cannot be undone.' }), list, error, el('div', { className: 'actions' }, cancel, confirm));
  dialog.addEventListener('close', () => { view.cancel(); dialog.remove(); });
  document.body.append(dialog);
  dialog.showModal();
}

// After a transaction was sent (or recorded with an uncertain submission —
// `warning`): track it until its receipt (or until it can no longer be
// included). A polling error leaves the transaction pending in Activity:
// the next one is prepared only once Activity resolves it.
function track(sent, title, extra = {}, warning = '') {
  const row = { intentId: sent.intentId, title, state: 'pending', warning, ...extra };
  recent.unshift(row);
  if (recent.length > 20) recent.pop();
  const gen = generation;
  if (warning) status = warning;
  sessionLog.log('evm', `${title}: submitted${warning ? ` — ${warning}` : ''}`, { error: !!warning });
  render();
  sent.receipt.then(result => {
    if (gen !== generation) return;
    row.state = result.status; row.result = result.receipt || null;
    sessionLog.log('evm', `${title}: ${result.status}`);
    row.createdCheck = result.createdCheck; row.createdExpected = result.createdExpected;
    for (const id of result.receipt?.tickets || []) void lookTicket(id);
    void refreshBalance();
    render();
  }, error => {
    if (gen !== generation) return;
    row.state = 'unknown'; row.error = `${error?.message || 'No answer yet.'} It stays pending in Activity until it is included or its expiry block passes.`;
    sessionLog.log('evm', `${title}: ${row.error}`, { error: true });
    render();
  });
}

async function prepareAndShow(prepare, title, extra) {
  await act(async gen => {
    const view = await prepare();
    if (gen !== generation) { view.cancel(); return; }
    showReview(view, title, (sent, warning) => track(sent, title, extra, warning));
  });
}

// ── bridge: move NODUS in / out, tickets ────────────────────────────────

async function lookTicket(id) {
  const gen = generation;
  try {
    const t = await account.ticket(id);
    if (gen === generation) tickets.set(id, t);
  } catch (error) { if (gen === generation) tickets.set(id, { error: error?.message || 'Unavailable.' }); }
  if (gen === generation) render();
}

function renderAccount() {
  const box = el('div', { className: 'stake-block' });
  const address = account.displayAddress;
  const copy = btn('Copy', () => { void navigator.clipboard?.writeText(address); });
  copy.dataset.always = '1';
  box.append(el('h4', { text: 'Your smart-contract account' }),
    el('div', { className: 'address-row' }, el('code', { text: address }), copy),
    el('p', { className: 'hint', text: 'This address belongs to your wallet: it is made from your Nodus address, so only your wallet can act for it. It is not an Ethereum address; do not send coins from other networks to it.' }));
  const line = !client.evmReadable ? 'Balance not shown: this wallet version cannot read smart-contract balances yet.'
    : balance ? `Balance: ${formatWei(balance.wei)} NODUS (at block ${balance.height})` : 'Balance: loading…';
  box.append(el('p', { text: line }), btn('Refresh', () => void act(() => refreshBalance())));
  if (account.waiting()) box.append(el('p', { className: 'hint', text: 'A transaction of this account is still waiting to be included (see Activity). The next one is prepared after it.' }));
  return box;
}

function renderBridge() {
  const box = el('div', { className: 'stake-block' });
  const inAmount = input({ placeholder: '0.0' });
  const outAmount = input({ placeholder: '0.0' });
  const outTo = input({ value: client.fingerprint, mono: true });
  box.append(
    el('h4', { text: 'Move NODUS to smart contracts' }),
    el('p', { className: 'hint', text: 'Moves NODUS from your Nodus address into your smart-contract balance, where contracts can use it.' }),
    ...field('Amount (NODUS)', inAmount),
    btn('Review', () => void prepareAndShow(() => account.deposit(parseRaw(inAmount.value)), 'Move NODUS to smart contracts'), ''),
    el('h4', { text: 'Move NODUS back' }),
    el('p', { className: 'hint', text: 'Moves NODUS from your smart-contract balance to a Nodus address — your own unless you change it. Only whole units of 0.00000001 NODUS can move back; anything smaller stays in your smart-contract balance.' }),
    ...field('Amount (NODUS)', outAmount),
    ...field('Pay to (Nodus address, 128 characters)', outTo),
    btn('Review', () => void prepareAndShow(() => {
      const to = outTo.value.trim().toLowerCase();
      if (!HEX128.test(to)) throw new Error('Enter a Nodus address: 128 characters, 0-9 and a-f.');
      const raw = parseRaw(outAmount.value);
      if (balance && raw * 10n ** 10n > balance.wei) throw new Error(`Your smart-contract balance is ${formatWei(balance.wei)} NODUS; at most ${formatRaw(weiToRaw(balance.wei).raw)} NODUS can move back.`);
      return account.withdraw(raw, to);
    }, 'Move NODUS back'), ''));
  return box;
}

function renderTickets() {
  const box = el('div', { className: 'stake-block' });
  box.append(el('h4', { text: 'Withdrawal tickets' }),
    el('p', { className: 'hint', text: 'A contract can pay NODUS out to a Nodus address by writing a withdrawal ticket. Collecting a ticket pays it to that address. Tickets your transactions created appear here; you can also add one by its number.' }));
  const list = el('div', { className: 'stake-list' });
  if (!tickets.size) list.append(el('p', { className: 'stake-empty', text: 'No tickets.' }));
  for (const [id, t] of tickets) {
    const row = el('div', { className: 'stake-row' });
    if (t.error) {
      row.append(el('span', { text: `Ticket ${short(id)}` }), el('span', { className: 'hint', text: t.error }));
    } else {
      row.append(el('span', { text: `Ticket ${short(id)} · ${nodus(t.amountRaw)}` }),
        el('span', { className: 'hint', text: t.pending ? (t.dest === client.fingerprint ? 'pays you' : `pays ${short(t.dest)}`) : 'collected' }));
      if (t.pending && client.evmBuildable) {
        const actions = el('div', { className: 'stake-actions' });
        actions.append(btn('Collect', () => void prepareAndShow(() => account.redeem(id, t.dest), 'Collect a withdrawal ticket')));
        row.append(actions);
      }
    }
    list.append(row);
  }
  const add = input({ placeholder: 'Ticket number (128 characters)', mono: true });
  box.append(list, ...field('Add a ticket', add), btn('Look up', () => void act(async () => {
    const id = add.value.trim().toLowerCase();
    if (!HEX128.test(id)) throw new Error('A ticket number has 128 characters, 0-9 and a-f.');
    await lookTicket(id);
  })));
  return box;
}

// ── contracts ───────────────────────────────────────────────────────────

// One text field per parameter: plain text for a single value, JSON for a
// list or a group of values (large numbers in quotes).
function argField(name, node) {
  const kind = typeString(node);
  const complex = node.kind === 'array' || node.kind === 'tuple';
  return { node, input: input({ placeholder: complex ? `${kind} as JSON, e.g. ["1","2"]` : kind, mono: true }), label: `${name || 'value'} (${kind})` };
}
function argValue({ node, input: box }) {
  const text = box.value.trim();
  if (node.kind === 'array' || node.kind === 'tuple') {
    try { return JSON.parse(text); } catch { throw new Error(`${box.placeholder}: not valid JSON.`); }
  }
  if (node.kind === 'bool') {
    if (text !== 'true' && text !== 'false') throw new Error('Enter true or false.');
    return text === 'true';
  }
  return text;
}
const show = v => (typeof v === 'bigint' ? v.toString() : Array.isArray(v) ? `[${v.map(show).join(', ')}]` : String(v));

function renderContractLoad() {
  const box = el('div', { className: 'stake-block' });
  const addr = input({ placeholder: '0x… (64 hex characters)', mono: true });
  const abi = area('Contract ABI (JSON)');
  const code = area('Contract bytecode (0x…), only to deploy a new contract');
  box.append(el('h4', { text: 'Use a contract' }),
    el('p', { className: 'hint', text: 'Paste the contract’s address and its ABI (the description of its functions, given by whoever wrote it). To put a new contract on the network, paste its bytecode and ABI instead and choose “Deploy”.' }),
    ...field('Contract address', addr), ...field('ABI', abi), ...field('Bytecode', code));
  if (contractError) box.append(el('p', { className: 'hint', text: contractError }));
  box.append(btn('Open contract', () => {
    contractError = ''; readResults.clear();
    try { contract = new Contract({ account, address: addr.value, abi: abi.value }); } catch (error) { contract = null; contractError = error?.message || 'This contract could not be opened.'; }
    render();
  }, ''), btn('Deploy…', () => {
    contractError = '';
    try {
      const iface = new Interface(abi.value);
      const hex = code.value.trim();
      if (!/^0x([0-9a-fA-F]{2})+$/.test(hex)) throw new Error('Paste the bytecode as 0x followed by hex.');
      deployDraft = { iface, bytecode: hex, args: (iface.constructorEntry?.inputs || []).map((n, i) => argField(iface.constructorEntry.inputNames[i], n)) };
    } catch (error) { contractError = error?.message || 'This contract could not be prepared.'; }
    render();
  }));
  return box;
}

function renderDeploy() {
  const box = el('div', { className: 'stake-block' });
  box.append(el('h4', { text: 'Deploy a new contract' }));
  for (const a of deployDraft.args) box.append(...field(a.label, a.input));
  const value = deployDraft.iface.constructorEntry?.payable ? input({ placeholder: '0.0' }) : null;
  if (value) box.append(...field('Send with it (NODUS)', value));
  box.append(btn('Review deployment', () => void prepareAndShow(() => Contract.prepareDeploy({
    account, bytecode: deployDraft.bytecode, abi: deployDraft.iface, args: deployDraft.args.map(argValue), valueWei: value && value.value.trim() ? parseWei(value.value) : 0n
  }), 'Deploy a contract', { iface: deployDraft.iface }), ''), btn('Close', () => { deployDraft = null; render(); }));
  return box;
}

function renderContract() {
  const box = el('div', { className: 'stake-block' });
  box.append(el('h4', { text: `Contract ${toChecksumAddress(contract.address)}` }), btn('Close contract', () => { contract = null; readResults.clear(); render(); }));
  const list = el('div', { className: 'stake-list' });
  for (const fn of contract.iface.functions) {
    const row = el('div', { className: 'stake-row evm-fn' });
    const args = fn.inputs.map((n, i) => argField(fn.inputNames[i], n));
    row.append(el('span', { text: fn.signature }), el('span', { className: 'hint', text: fn.readOnly ? 'read' : fn.payable ? 'write, accepts NODUS' : 'write' }));
    const form = el('div', { className: 'stake-actions' });
    for (const a of args) form.append(...field(a.label, a.input));
    const value = fn.payable ? input({ placeholder: '0.0' }) : null;
    if (value) form.append(...field('Send with it (NODUS)', value));
    if (fn.readOnly) {
      form.append(btn('Read', () => void act(async gen => {
        const r = await contract.read(fn, args.map(argValue));
        if (gen !== generation) return;
        readResults.set(fn.signature, r.values.map((v, i) => `${r.names[i] || `#${i + 1}`}: ${show(v)}`).join(' · ') || '(no result)');
      })));
    } else if (client.evmBuildable) {
      form.append(btn('Review', () => void prepareAndShow(() => contract.prepareSend(fn, args.map(argValue), { valueWei: value && value.value.trim() ? parseWei(value.value) : 0n }), `Call ${fn.name}`, { iface: contract.iface }), ''));
    }
    row.append(form);
    if (readResults.has(fn.signature)) row.append(el('p', { className: 'hint', text: readResults.get(fn.signature) }));
    list.append(row);
  }
  if (!contract.iface.functions.length) list.append(el('p', { className: 'stake-empty', text: 'This ABI has no functions.' }));
  box.append(list);
  return box;
}

// ── recent transactions ─────────────────────────────────────────────────

const STATE_TEXT = {
  pending: 'Waiting to be included',
  'applied-success': 'Done',
  'applied-failed': 'Ran but failed — the network fee was charged',
  refused: 'Not included — nothing was charged',
  unknown: 'No answer yet'
};
function renderRecent() {
  const box = el('div', { className: 'stake-block' });
  box.append(el('h4', { text: 'Recent smart-contract transactions' }));
  const list = el('div', { className: 'activity-list' });
  for (const row of recent) {
    const item = el('div', { className: 'activity-row' });
    item.append(el('span', { text: row.title }), el('span', { className: 'hint', text: STATE_TEXT[row.state] || row.state }));
    const details = [];
    const r = row.result;
    if (row.warning) details.push(row.warning);
    if (r) {
      // a receipt's `h` is the inclusion height (design §18 rev 5); the
      // whole receipt is the connected node's report (F11)
      details.push(`Included in block ${r.height}; gas used ${r.gasUsed} — as reported by the connected Nodus node (not proven against the chain).`);
      if (row.createdCheck === 'mismatch') {
        details.push(`Warning: the node reports the new contract at ${r.created ? toChecksumAddress(r.created) : 'no address'}, but this deployment's address is ${toChecksumAddress(row.createdExpected)} (computed from the transaction you signed). Do not use the node's address.`);
      } else if (row.createdCheck === 'match') {
        details.push(`New contract: ${toChecksumAddress(r.created)} (matches the address computed from the transaction you signed)`);
      } else if (r.created) {
        details.push(`New contract: ${toChecksumAddress(r.created)} (as reported by the node; not checked)`);
      }
      if (r.tickets.length) details.push(`Withdrawal tickets: ${r.tickets.map(short).join(', ')}`);
      if (r.weiDestroyed > 0n) details.push(`Value removed from circulation by the contract: ${formatWei(r.weiDestroyed)} NODUS`);
      for (const lg of r.logs) {
        const ev = row.iface ? safeParse(row.iface, lg) : null;
        details.push(ev ? `Event ${ev.name}(${describeArgs(ev.args.map(a => a.name), ev.args.map(a => a.value))})` : `Event from ${short(lg.address)} (${lg.topics.length} topics, ${lg.data.length / 2} bytes)`);
      }
    }
    if (row.error) details.push(row.error);
    details.push(`Transaction ${short(row.intentId)}`);
    for (const d of details) item.append(el('p', { className: 'hint', text: d }));
    list.append(item);
  }
  if (!recent.length) list.append(el('p', { className: 'stake-empty', text: 'None in this session.' }));
  box.append(list);
  return box;
}
function safeParse(iface, lg) {
  try { return iface.parseLog({ topics: lg.topics.map(t => `0x${t}`), data: `0x${lg.data}` }); } catch { return null; }
}

// ── panel ───────────────────────────────────────────────────────────────

function showPanel() {
  if (!panel) return;
  const ready = !!client && client.state === 'ready' && (client.evmBuildable || client.evmReadable);
  panel.hidden = !(ready && $('chain')?.value === NODUS_ASSET.chain);
  const nav = $('nav-evm');
  if (nav) nav.hidden = panel.hidden;
}

function render() {
  showPanel();
  if (!root) return;
  if (!client || !account) { root.replaceChildren(); return; }
  const line = el('p', { className: 'hint', text: status });
  line.setAttribute('role', 'status'); line.setAttribute('aria-live', 'polite');
  const items = [el('p', { className: 'hint', text: 'Smart contracts are programs that run on the Nodus network. Your wallet signs every transaction after you check it; the network fee shown is the most a transaction can cost.' }), line, renderAccount()];
  if (client.evmBuildable) items.push(renderBridge());
  if (client.evmReadable) items.push(renderTickets());
  items.push(deployDraft ? renderDeploy() : contract ? renderContract() : renderContractLoad(), renderRecent());
  root.replaceChildren(...items);
  if (busy) for (const b of root.querySelectorAll('button')) if (!b.dataset.always) b.disabled = true;
}

export function mountSmartContracts({ panelNode, rootNode }) {
  panel = panelNode; root = rootNode;
  $('chain')?.addEventListener('change', showPanel);
  render();
}

export const smartContractExtension = {
  nodusReady(detail) { start(detail); },
  nodusClosing() { reset(); },
  nodusUnavailable() { reset(); },
  vaultDeleting() { reset(); },
  locked() { reset(); }
};
