import { formatUnits } from '../../../src/core.js';
import { shortKey } from '../../../src/adapters/nodus.js';
import { NODUS_ASSET } from '../../../src/nodus/network.js';

// Rendering port of src/app.js:1436-1575. Only adapter reads/builds cross
// the trusted port; decoded review rows use the wallet's common dialog.
export function mountEarn({ root, document, ui, selected, portfolio, run, showReview, navigate }) {
  const $ = id => root.querySelector('#' + id);
  let stakeView, expandedValidator, generation = 0, disposed = false, available = false;
  const groupDigits = text => { const [whole, fraction] = text.split('.'); return whole.replace(/\B(?=(\d{3})+(?!\d))/g, ',') + (fraction ? `.${fraction}` : ''); };
  const nodusAmountText = units => groupDigits(formatUnits(units, NODUS_ASSET.decimals));
  const startStake = (kind, params) => run(async () => {
    const check = generation, prepared = await ui.request('prepareStake', [kind, params]);
    if (disposed || check !== generation) { await ui.cancelNodusSend(prepared.id); return; }
    showReview(prepared, { chain: 'nodus', title: kind === 'delegate' ? 'Review delegation' : 'Review undelegation' });
  });
function renderNetworkStake(network) {
  const box = $('stake-network');
  const label = document.createElement('span'); label.className = 'stake-network-label'; label.textContent = 'Staked on the network';
  const total = document.createElement('strong'); total.textContent = `${network.partial ? 'at least ' : ''}${nodusAmountText(network.total)} NODUS`;
  const detail = document.createElement('small');
  detail.textContent = `${nodusAmountText(network.selfStake)} NODUS in witness bonds and ${nodusAmountText(network.delegated)} NODUS delegated, across ${network.witnesses} witness${network.witnesses === 1 ? '' : 'es'}${network.partial ? ' (only the first witnesses are listed)' : ''}.`;
  box.replaceChildren(label, total, detail); box.hidden = false;
}
async function refreshStaking() {
  const client = nodusClient, source = wallet, check = ++stakeCheck;
  if (!client || !source || source.locked || !client.stakeable) { hideStaking(); return; }
  const current = () => check === stakeCheck && client === nodusClient && source === wallet && !source.locked;
  setEarnAvailable(true); $('stake-status').textContent = 'Reading witnesses and your delegations…';
  try {
    const view = await adapters.nodus.stakingOverview({ client, from: source.addresses.nodus });
    if (!current()) return;
    stakeView = view; renderStaking(view); renderNetworkStake(view.network);
    $('stake-status').textContent = view.truncated ? 'The witness list is longer than this wallet shows; only the first witnesses are listed.' : '';
  } catch (error) {
    if (!current()) return;
    $('stake-status').textContent = `Could not read witnesses or delegations: ${error?.message || 'unknown error'} Use Refresh to try again.`;
  }
}
function renderStaking(view) {
  const { rules } = view;
  const minText = nodusAmountText(rules.minDelegation);
  const rate = bps => `${(bps / 100).toFixed(2).replace(/\.?0+$/, '')}%`;
  // Rows are laid out like portfolio holding rows (src/portfolio-view.js):
  // identity and figures on the left, status on the right. The whole row
  // header is one button that opens or closes the row's own delegation
  // controls below it.
  const el = (tag, className, text) => { const node = document.createElement(tag); node.className = className; if (text !== undefined) node.textContent = text; return node; };
  const mine = new Map(view.delegations.map(d => [d.validator, d]));
  if (expandedValidator && !view.validators.some(v => v.fingerprint === expandedValidator)) expandedValidator = undefined;
  // What was typed in the open row survives this redraw (a background
  // re-read, e.g. another transaction becoming final): only the amounts the
  // person edited — the withdraw box's pre-filled amount follows the new
  // figures — and only while the same row stays open. Keyboard focus and the
  // cursor position in that box come back too. Closing the row, or opening
  // another one, drops it.
  const drafts = new Map(); let focused;
  const shown = $('validator-list').querySelector('.stake-detail');
  if (expandedValidator && shown?.dataset.validator === expandedValidator) {
    for (const input of shown.querySelectorAll('input[data-field]')) {
      if (input.dataset.edited) drafts.set(input.dataset.field, input.value);
      if (input === document.activeElement) focused = { field: input.dataset.field, start: input.selectionStart, end: input.selectionEnd };
    }
  }
  const amountInput = (label, field, value = '') => {
    const input = document.createElement('input'); input.inputMode = 'decimal'; input.autocomplete = 'off'; input.spellcheck = false; input.placeholder = '0.00';
    input.dataset.field = field;
    if (drafts.has(field)) { input.value = drafts.get(field); input.dataset.edited = 'true'; } else input.value = value;
    input.addEventListener('input', () => { input.dataset.edited = 'true'; });
    input.setAttribute('aria-label', label); return input;
  };
  const actionButton = (text, run) => { const button = el('button', 'small', text); button.type = 'button'; button.onclick = () => void run(button); return button; };
  $('validator-list').replaceChildren(...(view.validators.length ? view.validators.map(v => {
    const short = shortKey(v.fingerprint), d = mine.get(v.fingerprint), open = expandedValidator === v.fingerprint;
    // Filled delegator places of the chain's per-validator cap; '?' when the
    // node's answer carries no count (an older node) — never shown as 0.
    const slots = `${v.delegators === null ? '?' : v.delegators}/${rules.maxDelegators}`;
    const full = v.delegators !== null && BigInt(v.delegators) >= rules.maxDelegators;
    const row = el('div', 'stake-row');
    row.title = v.fingerprint;
    const toggle = el('button', 'stake-row-toggle'); toggle.type = 'button';
    toggle.setAttribute('aria-expanded', String(open));
    toggle.setAttribute('aria-label', `Witness ${short}${d ? `, your delegation ${nodusAmountText(d.amount)} NODUS` : ''}. ${open ? 'Close' : 'Open'} delegation controls`);
    const name = el('span', 'stake-main');
    name.append(el('strong', '', short),
      el('small', '', `own stake ${nodusAmountText(v.selfStake)} NODUS · delegated ${nodusAmountText(v.delegated)} NODUS · commission ${rate(v.commissionBps)} · delegators ${slots}`));
    if (d) name.append(el('small', 'stake-mine', `Your delegation: ${nodusAmountText(d.amount)} NODUS`));
    const badge = el('span', 'status-badge', v.statusText); badge.dataset.status = v.status;
    toggle.append(name, badge);
    toggle.dataset.validator = v.fingerprint;
    // The list is drawn again; keyboard focus returns to this row's header.
    toggle.onclick = () => {
      expandedValidator = open ? undefined : v.fingerprint; renderStaking(view);
      $('validator-list').querySelector(`button[data-validator="${v.fingerprint}"]`)?.focus({ preventScroll: true });
    };
    row.append(toggle);
    if (!open) return row;
    const detail = el('div', 'stake-detail');
    detail.dataset.validator = v.fingerprint;
    if (d) {
      detail.append(el('p', 'hint', `You have ${nodusAmountText(d.amount)} NODUS delegated to this witness.`));
      if (v.acceptsDelegation) {
        const more = amountInput(`Amount to add to your delegation with ${short}`, 'more');
        const add = el('span', 'stake-actions');
        add.append(more, actionButton('Review adding more', button => startStake('delegate', { validator: v.fingerprint, amount: more.value }, button)));
        detail.append(add, el('p', 'hint', 'Adding to your delegation can be any amount. A network fee is paid on top.'));
      } else detail.append(el('p', 'hint', `This witness does not take more delegations now (${v.statusText}).`));
      const back = amountInput(`Amount to withdraw from ${short}`, 'withdraw', formatUnits(d.amount, NODUS_ASSET.decimals));
      const withdraw = el('span', 'stake-actions');
      withdraw.append(back, actionButton('Review withdrawal', button => startStake('undelegate', { validator: v.fingerprint, amount: back.value }, button)));
      detail.append(withdraw, el('p', 'hint', `Withdrawing returns the NODUS to your address as a separate coin that stays locked for ${view.lockText} after the witness set next changes. Until then it cannot be sent or delegated again. Withdraw everything, or leave at least ${minText} NODUS delegated. The network fee is paid from your spendable NODUS.`));
    } else if (!v.acceptsDelegation) {
      detail.append(el('p', 'hint', `This witness does not take delegations now (${v.statusText}).`));
    } else if (full) {
      detail.append(el('p', 'hint', `All ${rules.maxDelegators} delegator places of this witness are taken. Choose another witness.`));
    } else {
      const amount = amountInput(`Amount to delegate to ${short}`, 'amount');
      const actions = el('span', 'stake-actions');
      actions.append(amount, actionButton('Review delegation', button => startStake('delegate', { validator: v.fingerprint, amount: amount.value }, button)));
      detail.append(actions, el('p', 'hint', `A new delegation is at least ${minText} NODUS. A network fee is paid on top. You review every detail before anything is sent.`));
    }
    row.append(detail);
    return row;
  }) : [el('p', 'stake-empty', 'No witnesses listed.')]));
  if (focused) {
    const input = $('validator-list').querySelector(`.stake-detail input[data-field="${focused.field}"]`);
    if (input) {
      input.focus({ preventScroll: true });
      if (focused.start !== null && focused.end !== null) input.setSelectionRange(Math.min(focused.start, input.value.length), Math.min(focused.end, input.value.length));
    }
  }
  // A delegation whose validator is not in the list above has no row to
  // live on; it is listed here (it cannot be withdrawn from this page: the
  // module needs the validator's key from the list).
  const unlisted = view.delegations.filter(d => !d.canUndelegate);
  $('unlisted-delegations').hidden = unlisted.length === 0;
  $('delegation-list').replaceChildren(...unlisted.map(d => {
    const row = el('div', 'stake-row');
    const name = el('span', 'stake-main');
    name.append(el('strong', '', `${nodusAmountText(d.amount)} NODUS`), el('small', '', `with ${shortKey(d.validator)}`));
    row.append(name);
    row.title = d.validator;
    const actions = el('span', 'stake-actions');
    actions.append(el('small', 'stake-note', '(this witness is not in the list above, so it cannot be withdrawn from here)'));
    row.append(actions);
    return row;
  }));
}

  async function refresh() {
    if (!available || disposed) return;
    const check = ++generation; $('stake-status').textContent = 'Reading witnesses and your delegations…';
    try {
      const view = await ui.request('getStakingOverview');
      if (disposed || check !== generation) return;
      stakeView = view; renderStaking(view); renderNetworkStake(view.network);
      $('stake-status').textContent = view.truncated ? 'The witness list is longer than this wallet shows; only the first witnesses are listed.' : '';
    } catch (error) {
      if (!disposed && check === generation) $('stake-status').textContent = `Could not read witnesses or delegations: ${error.message} Use Refresh to try again.`;
    }
  }
  $('stake-refresh').onclick = () => run(refresh);
  $('quick-earn').onclick = () => navigate('earn');
  function update() {
    const next = selected() === 'nodus' && !!ui.state.nodus?.stakeable, changed = next !== available;
    available = next; $('quick-earn').disabled = !next; $('quick-earn').title = next ? '' : 'Earn opens once the wallet is connected to the Nodus network.';
    $('nav-earn').hidden = $('stake-panel').hidden = !next; portfolio.setEarn('nodus', next);
    if (changed) { generation++; if (next) void refresh(); else { stakeView = undefined; expandedValidator = undefined; $('validator-list').replaceChildren(); $('delegation-list').replaceChildren(); $('stake-network').hidden = true; } }
  }
  return { update, refresh, sent() { expandedValidator = undefined; if (stakeView) renderStaking(stakeView); void refresh(); }, dispose() { disposed = true; generation++; stakeView = undefined; } };
}

