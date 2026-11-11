// swap.nodusnetwork.io: DOM wiring only. The logic is in swap-logic.js, the bot client in bot.js, the order of the
// steps in flow.js, the extension's existing methods in extension.js and its new methods in adapter.js.
// Every string that comes from the bot is written with textContent. No inline script or style (CSP, deploy/swap-https.conf).
import { createBotClient, BOT_ORIGIN } from './bot.js';
import { createExtension } from './extension.js';
import { createAdapter } from './adapter.js';
import { createSwapFlow } from './flow.js';
import {
  USDT_DECIMALS, NODUS_DECIMALS, outputUnit, displayAmount, percentToBps, priceFromReserves, refusalText, nodusWithCommas, STILL_PENDING_TEXT,
} from './swap-logic.js';

const $ = id => document.getElementById(id);
const short = v => (v.length > 14 ? `${v.slice(0, 6)}…${v.slice(-4)}` : v);
const EXT_PAGE = 'https://nodusnetwork.io/extension.html';

const extension = createExtension();
// The bot address given to the extension is the bot's own https origin, no path (BOT_ORIGIN, bot.js); the extension
// appends /amm/swap itself (givens item 97; the extension's botOrigin accepts an https origin only). The page's own
// calls go to the same origin (the client's default base), so the two cannot differ. Never the page's own origin.
const botUrl = BOT_ORIGIN;
const bot = createBotClient({ fetch: (...a) => fetch(...a) });
const adapter = createAdapter({ getProvider: () => extension.provider() });
const flow = createSwapFlow({
  bot, adapter, botUrl,
  signText: (text, address) => extension.signNodusText(text, address),
});

let direction = 'usdt_to_nodus'; // what the user pays
const unitOf = which => (which === 'usdt' ? { name: 'USDT', decimals: USDT_DECIMALS } : { name: 'NODUS', decimals: NODUS_DECIMALS });
const amountOut = (raw, unit) => `${displayAmount(raw, unit.decimals)} ${unit.name}`;

function say(el, text, bad = false) {
  el.textContent = text; el.hidden = !text; el.classList.toggle('bad', bad);
}
function pill(el, which) {
  const i = document.createElement('i'), small = document.createElement('small');
  i.className = which === 'usdt' ? 'usdt' : 'nodus'; i.textContent = which === 'usdt' ? '₮' : 'N';
  small.textContent = which === 'usdt' ? 'Ethereum' : 'Nodus';
  el.replaceChildren(i, document.createTextNode(which === 'usdt' ? 'USDT ' : 'NODUS '), small);
}
function renderTokens() {
  pill($('pay-token'), direction === 'usdt_to_nodus' ? 'usdt' : 'nodus');
  pill($('get-token'), direction === 'usdt_to_nodus' ? 'nodus' : 'usdt');
}

// ── what the page shows about the quote ──
function resetQuote() {
  flow.clearQuote('swap');
  $('get').value = '';
  for (const id of ['d-fee', 'd-min', 'd-request', 'd-valid']) $(id).textContent = '—';
  $('approve-btn').hidden = true; $('ask-btn').hidden = false;
}
function resetAddQuote() {
  flow.clearQuote('add');
  $('liq-approve').hidden = true; $('liq-ask').hidden = false;
  for (const id of ['l-usdt', 'l-nodus', 'l-request', 'l-valid']) $(id).textContent = '—';
}
const time = unix => new Date(Number(unix) * 1000).toLocaleTimeString();

function renderMinimum() {
  const q = flow.state.quote;
  if (!q) return;
  const t = percentToBps($('tol').value);
  if (!t.ok) { $('d-min').textContent = '—'; $('approve-btn').disabled = true; return; }
  $('d-min').textContent = amountOut(flow.minimumFor(t.bps), outputUnit(q.direction));   // the quote's own direction
  $('approve-btn').disabled = !flow.state.accounts;
}

function renderStatus(status) {
  const p = priceFromReserves(status.reserves);
  $('d-price').textContent = p ? `1 USDT ≈ ${p.nodusPerUsdt} NODUS` : 'No price yet';
  const c = status.settings.commission;
  $('d-commission').textContent = c === '0' ? 'None' : `${c} (bot setting)`;
  $('swap-limits').textContent = `Per swap, measured in USDT: at least ${displayAmount(BigInt(status.settings.swapMinUsdt), USDT_DECIMALS)}, ` +
    `at most ${displayAmount(BigInt(status.settings.swapMaxUsdt), USDT_DECIMALS)}. The extension shows the request in full before you sign.`;
  // The add minimum shown on the liquidity screen follows the bot's status (givens item 96); the bot's refusal governs.
  const minNote = document.querySelector('#panel-liq .field-foot span');
  if (minNote) minNote.textContent = `At least ${nodusWithCommas(flow.liquidityMin())} NODUS, with the USDT at the pool's current ratio.`;
  const notes = [];
  if (status.stopped) notes.push('The bot has stopped taking new swaps.');
  if (status.swapsPaused) notes.push('Swaps are paused.');
  if (status.payoutsPaused) notes.push('Payouts are paused: swaps wait.');
  if (status.liquidityPaused) notes.push('Liquidity changes are paused.');
  say($('bot-status'), notes.join(' '), true);
}

async function loadStatus() {
  const r = await flow.loadStatus();
  if (!r.ok) { say($('bot-status'), refusalText(r.reason), true); return; }
  try { renderStatus(r.status); } catch { say($('bot-status'), refusalText('bad_answer'), true); }
}

// ── connect (before or after arriving, givens item 68) ──
// No price or pair question before the extension is connected (givens item 68): the two ask buttons stay disabled and
// a hint stands in the message line until a connect succeeds. flow.press and flow.pressAdd refuse as well.
const connected = () => Boolean(flow.state.accounts);
const ASK_HINT = { 'swap-msg': 'Connect the extension to ask for a price.', 'liq-msg': 'Connect the extension to ask for the pair.' };
// Clears a message line; while not connected the line shows the connect hint instead.
function clearMsg(id) { say($(id), connected() ? '' : ASK_HINT[id]); }
function renderAskButtons() {
  $('ask-btn').disabled = !connected(); $('liq-ask').disabled = !connected();
  clearMsg('swap-msg'); clearMsg('liq-msg');
}
renderAskButtons();
const connectBtn = $('connect-btn');
connectBtn.addEventListener('click', async () => {
  say($('connect-status'), '');
  connectBtn.disabled = true; connectBtn.textContent = 'Connecting…';
  try {
    const accounts = await extension.connect();
    flow.setAccounts(accounts);
    connectBtn.textContent = `${short(accounts.nodus.address)} · ${short(accounts.ethereum)}`;
    connectBtn.title = `Nodus ${accounts.nodus.address}\nEthereum ${accounts.ethereum}`;
    $('nodus-addr').textContent = short(accounts.nodus.address); $('nodus-addr').title = accounts.nodus.address;
    $('eth-addr').textContent = short(accounts.ethereum); $('eth-addr').title = accounts.ethereum;
    say($('connect-status'), 'Connected to Nodus Connect.');
    renderAskButtons();
    renderMinimum();
    renderWithdrawButton();   // a different account drops a kept signed withdrawal (flow.setAccounts)
  } catch (error) {
    connectBtn.disabled = false; connectBtn.textContent = 'Connect extension';
    if (error?.code === 'no_extension') {
      say($('connect-status'), 'The Nodus Connect extension was not found in this browser.');
      connectBtn.textContent = 'Get the extension'; connectBtn.onclick = () => { location.href = EXT_PAGE; };
    } else if (error?.code === 4001) say($('connect-status'), 'The connection was rejected in the extension.');
    else if (error?.code === 4100) say($('connect-status'), 'Open the extension and accept its data notice first, then connect again.');
    else say($('connect-status'), 'The extension did not connect. Unlock it and try again.');
  }
});

// ── tabs ──
function showTab(swap) {
  $('panel-swap').hidden = !swap; $('panel-liq').hidden = swap;
  $('tab-swap').setAttribute('aria-selected', String(swap)); $('tab-liq').setAttribute('aria-selected', String(!swap));
}
$('tab-swap').addEventListener('click', () => showTab(true));
$('tab-liq').addEventListener('click', () => showTab(false));

// ── swap ──
$('flip').addEventListener('click', () => {
  direction = direction === 'usdt_to_nodus' ? 'nodus_to_usdt' : 'usdt_to_nodus';
  renderTokens(); resetQuote(); clearMsg('swap-msg');
});
// Every edit resets, even when no quote is stored yet: an answer still on its way is discarded by the flow.
$('pay').addEventListener('input', () => { resetQuote(); clearMsg('swap-msg'); });
$('tol').addEventListener('input', renderMinimum);
// Enter in the tolerance field must not send a second price question.
$('tol').addEventListener('keydown', event => { if (event.key === 'Enter') event.preventDefault(); });
for (const chip of document.querySelectorAll('.chip')) {
  chip.addEventListener('click', () => { $('tol').value = chip.dataset.pct; renderMinimum(); });
}

// The ONLY place the swap question is sent: the user's press (plan section 7 step 3).
$('swap-form').addEventListener('submit', async event => {
  event.preventDefault();
  say($('swap-msg'), '');
  const button = $('ask-btn');
  button.disabled = true;
  try {
    const r = await flow.press({ direction, amountText: $('pay').value });
    if (r.stale) return;   // the inputs changed while the bot was answering: that answer is not shown
    if (!r.ok) { say($('swap-msg'), r.text, true); return; }
    const q = r.quote, unit = outputUnit(q.direction);
    $('get').value = displayAmount(BigInt(q.number), unit.decimals);
    $('d-fee').textContent = amountOut(BigInt(q.estimatedFee), unit);
    $('d-request').textContent = q.requestNumber;
    $('d-valid').textContent = time(q.validUntil);
    $('step-approved').classList.add('done'); $('step-approved-t').textContent = time(Math.floor(Date.now() / 1000));
    button.hidden = true; $('approve-btn').hidden = false;
    renderMinimum();
    say($('swap-msg'), 'Choose your tolerance, then approve in the extension.');
  } finally { button.disabled = !connected(); }
});

// `unit` is the output's unit of the swap being followed (NODUS for USDT -> NODUS, USDT for NODUS -> USDT), fixed
// when the swap starts so a later flip of the direction does not change how its numbers are shown.
function renderState({ info, answer }, unit) {
  $('state-text').textContent = info.text;
  $('state-word').textContent = info.state || '';
  $('step-state').classList.toggle('done', info.final);
  $('step-state').classList.toggle('now', !info.final);
  const showResult = Boolean(answer) && (answer.output !== undefined || answer.reason !== undefined);
  $('result').hidden = !showResult;
  if (showResult) {
    const asAmount = v => (v !== undefined && /^\d+$/.test(String(v)) ? amountOut(BigInt(v), unit) : '—');
    $('r-output').textContent = asAmount(answer.output);
    $('r-fee').textContent = asAmount(answer.networkFee);
    $('r-paid').textContent = asAmount(answer.paid);
    $('r-reason').textContent = answer.reason ?? '—';
  }
}

// A new follow ends the older one (flow.follow): the older one's reads, result, exhaustion message and "Check again"
// handler no longer touch the panel, which always shows the request number being followed.
async function followSwap(requestNumber, unit) {
  $('check-again').hidden = true; $('check-again').onclick = null; say($('state-note'), '');
  $('follow-request').textContent = `Following request ${requestNumber}`; $('follow-request').hidden = false;
  $('state-text').textContent = 'Reading the swap from the bot.'; $('state-word').textContent = '';
  $('step-state').classList.remove('done'); $('step-state').classList.add('now'); $('result').hidden = true;
  const r = await flow.follow(requestNumber, update => renderState(update, unit));
  if (r.stopped) return;
  if (r.exhausted) {
    say($('state-note'), STILL_PENDING_TEXT);
    $('check-again').hidden = false;
    $('check-again').onclick = () => followSwap(requestNumber, unit);
  }
}

// The user's yes: the extension signs, sends the signed request to the bot and pays (plan section 7 steps 4-5).
$('approve-btn').addEventListener('click', async () => {
  const t = percentToBps($('tol').value);
  if (!t.ok) { say($('swap-msg'), 'Type a tolerance from 0 to 100 percent first.', true); return; }
  say($('swap-msg'), 'Approve the request in the extension.');
  $('approve-btn').disabled = true;
  const unit = outputUnit(flow.state.quote?.direction ?? direction);   // the approved quote's own direction
  const r = await flow.confirm({ toleranceBps: t.bps });
  if (!r.ok && r.delivered) {
    // The bot holds this request number: the approval is not offered again (a new price is needed); the swap is followed.
    say($('swap-msg'), r.text, true);
    $('approve-btn').hidden = true; $('approve-btn').disabled = false; $('ask-btn').hidden = false;
    await followSwap(r.requestNumber, unit);
    return;
  }
  if (!r.ok) {
    say($('swap-msg'), r.text, true);
    $('approve-btn').disabled = false;
    if (r.openRequestNumber) await followSwap(r.openRequestNumber, unit); // givens item 57: show the open swap
    return;
  }
  say($('swap-msg'), 'Request sent and payment made by the extension.');
  $('step-paid').classList.add('done'); $('step-paid-t').textContent = time(Math.floor(Date.now() / 1000));
  await followSwap(r.requestNumber, unit);
});

// ── liquidity ──
$('liq-amount').addEventListener('input', () => { resetAddQuote(); clearMsg('liq-msg'); });
$('liq-side').addEventListener('change', () => { resetAddQuote(); clearMsg('liq-msg'); });
$('liq-form').addEventListener('submit', async event => {
  event.preventDefault();
  say($('liq-msg'), '');
  $('liq-ask').disabled = true;
  try {
    const r = await flow.pressAdd({ side: $('liq-side').value, amountText: $('liq-amount').value });
    if (r.stale) return;   // the amount or side changed while the bot was answering: that answer is not shown
    if (!r.ok) { say($('liq-msg'), r.text, true); return; }
    const q = r.quote;
    $('l-usdt').textContent = amountOut(BigInt(q.usdtAmount), unitOf('usdt'));
    $('l-nodus').textContent = amountOut(BigInt(q.nodusAmount), unitOf('nodus'));
    $('l-request').textContent = q.requestNumber;
    $('l-valid').textContent = time(q.validUntil);
    $('liq-ask').hidden = true; $('liq-approve').hidden = false;
    say($('liq-msg'), 'These are the exact amounts. Approve in the extension to sign and pay both sides.');
  } finally { $('liq-ask').disabled = !connected(); }
});
$('liq-approve').addEventListener('click', async () => {
  say($('liq-msg'), 'Approve the requests in the extension.');
  $('liq-approve').disabled = true;
  const r = await flow.confirmAdd();
  $('liq-approve').disabled = false;
  if (!r.ok && r.delivered) {   // the bot holds the request: no second approval of this pair
    say($('liq-msg'), r.text, true);   // when NODUS was or may have been sent the text says not to ask for a new pair
    $('liq-approve').hidden = true; $('liq-ask').hidden = false;
    return;
  }
  if (!r.ok) { say($('liq-msg'), r.text, true); return; }
  say($('liq-msg'), 'Both requests were sent and both payments made by the extension. The add counts after 300 Ethereum blocks (at least one hour) and 3 Nodus blocks.');
});

// withdraw: nodus_signMessage (existing method) and a post by this site (plan 6.4.6, 6.4.7)
$('wd-form').addEventListener('submit', async event => {
  event.preventDefault();
  const bps = /^\d{1,5}$/.test($('wd-bps').value.trim()) ? Number($('wd-bps').value.trim()) : NaN;
  $('wd-btn').disabled = true;
  say($('wd-msg'), flow.pendingWithdrawNumber() ? 'Resending the same signed withdrawal; nothing new is signed.' : 'Approve the signature in the extension.');
  try {
    const r = await flow.withdraw({ basisPoints: bps });
    const received = `The bot received your withdrawal (request ${r.requestNumber}). It acts after the Ethereum wait; nothing is paid by this step.`;
    say($('wd-msg'), r.ok ? (r.text ?? received) : r.text, !r.ok);
  } finally { $('wd-btn').disabled = false; renderWithdrawButton(); }
});
// A signed withdrawal whose answer did not arrive is resent unchanged by the same button; the label says so.
function renderWithdrawButton() {
  $('wd-btn').textContent = flow.pendingWithdrawNumber() ? 'Resend the same signed withdrawal' : 'Sign and send the withdrawal';
}

renderTokens();
loadStatus(); // step 1: the price is read as soon as the page opens, connected or not
