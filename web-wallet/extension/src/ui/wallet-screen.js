import { WALLET_MARKUP } from './wallet-markup.js';
import { mountPortfolio } from './reference-portfolio.js';
import { CHAINS } from '../../../src/config.js';
import { NODUS_TOKEN_ID } from '../../../src/nodus/network.js';
import { autoLockBarText } from '../../../src/auto-lock.js';
import { netLevelFor, netStatusView } from '../../../src/net-status.js';
import { renderQr } from '../../../src/qr.js';
import { CHAIN_NETWORKS, chainNetwork } from '../constants/networks.js';
import { renderSites, renderSettings } from './views.js';
import { renderNodusHistory, renderNodusContracts } from './nodus-screens.js';
import { renderSolanaTronHistory } from './solana-tron-screens.js';
import { getAddress } from 'ethers';

// index.html:18-77 is the screen. This adapter passes only public form fields
// to wallet-ui.js; no wallet, derived key or signing implementation enters it.
export function mountReferenceWallet({ document, window, root, status, ui, run, loadBalances, lock, reveal, setAutoLock, clearReveal }) {
  const template = document.createElement('template'); template.innerHTML = WALLET_MARKUP;
  root.replaceChildren(template.content.cloneNode(true));
  const $ = id => root.querySelector('#' + id);
  $('wallet-status').replaceWith(status);
  root.className = '';
  for (const id of ['wallet-boot-status', 'welcome', 'unlock-form', 'phrase-form']) $(id).hidden = true;
  $('wallet-open').hidden = false;
  let selected = 'nodus', shownPage = null, disposed = false, readGeneration = 0, review, reviewTimer, contractResult, contractReview;
  let previousNetwork, previousTokens, previousAddress, walletScroll = 0;
  const isSolanaTron = chain => chain === 'solana' || chain === 'tron';
  function element(tag, text, className = '') {
    const node = document.createElement(tag); node.className = className;
    if (text !== undefined) node.textContent = text; return node;
  }
  const message = text => { status.textContent = text; status.className = 'result'; };
  const portfolio = mountPortfolio(document, root, () => ui.portfolioDetails(), selectAsset, () => run(async () => {
    portfolio.setBusy(true);
    try { await loadBalances(true); }
    finally { portfolio.setBusy(false); }
  }));
  // The dispatch defers these background methods. Retain the reference
  // controls, but do not attach page-owned substitutes for missing operations.
  for (const id of ['balance-refresh-minutes', 'show-zero-balances', 'vault-save', 'vault-change', 'address-book-save',
    'name-check', 'name-review', 'session-log-filter', 'session-log-copy', 'session-log-download']) $(id).disabled = true;
  $('balance-refresh-minutes').value = '0';
  for (const input of $('address-book-form').querySelectorAll('input, select')) input.disabled = true;
  $('address-book-form').onsubmit = event => event.preventDefault();
  $('lock').onclick = lock;

  // src/app.js:2083-2251: pages replace wallet-home, while both shortcuts lead
  // to the same, persistent Send / Receive panel. Hashes use the web names.
  function showPage(name, { focus = true } = {}) {
    const candidate = [...root.querySelectorAll('.wallet-page')].find(page => page.dataset.page === name);
    const page = candidate && !candidate.querySelector('.dashboard-panel').hidden ? candidate : null;
    const previous = shownPage;
    if (page && !previous) walletScroll = window.scrollY;
    if (shownPage === 'settings' && name !== 'settings') clearReveal();
    if (shownPage === 'contracts' && name !== 'contracts' && contractReview) {
      void ui.cancelNodusSend(contractReview.id).catch(() => {}); contractReview = undefined;
    }
    shownPage = page ? name : null;
    $('wallet-home').hidden = Boolean(page);
    for (const node of root.querySelectorAll('.wallet-page')) node.hidden = node !== page;
    if (page) {
      root.querySelector('.wallet-card').scrollIntoView({ block: 'start' });
      if (focus) page.querySelector('h3')?.focus({ preventScroll: true });
    } else if (previous) window.scrollTo(0, walletScroll);
    if (name === 'wallet-activity') void loadHistory();
    if (name === 'contracts') renderContracts();
  }
  function navigate(name) {
    window.history.replaceState(null, '', name ? `#${name}` : window.location.pathname + window.location.search);
    showPage(name);
  }
  for (const back of root.querySelectorAll('.page-back')) back.onclick = () => navigate(null);
  for (const link of root.querySelectorAll('.wallet-navigation a')) link.onclick = event => {
    event.preventDefault();
    const target = link.getAttribute('href').slice(1);
    if (target === 'assets-panel' || target === 'send-form') { navigate(null); $(target).scrollIntoView({ block: 'start' }); }
    else navigate(target);
  };
  const route = () => showPage(window.location.hash.slice(1));
  window.addEventListener('hashchange', route);
  $('quick-send').onclick = () => { navigate(null); $('send-block-title').focus({ preventScroll: true }); $('send-block').scrollIntoView({ block: 'start' }); };
  $('quick-receive').onclick = () => { navigate(null); $('receive-title').focus({ preventScroll: true }); $('receive-panel').scrollIntoView({ block: 'start' }); };
  function selectAsset(chain, symbol, action) {
    cancelReview(); selected = chain; $('chain').value = chain; selectChain(true);
    const option = [...$('asset').options].find(option => option.dataset.symbol === symbol);
    if (option) $('asset').value = option.value;
    applyAssetGate();
    if (action === 'choose') return;
    navigate(null);
    if (action === 'send' || action === 'receive') $(action === 'send' ? 'quick-send' : 'quick-receive').click();
    else if (window.matchMedia('(max-width: 900px)').matches) $('send-form').scrollIntoView({ block: 'start' });
  }
  function applyAssetGate() {
    const option = $('asset').selectedOptions[0];
    $('review-button').disabled = !option || option.disabled || ui.portfolioDetails().networks[selected].receiveOnly;
  }
  $('asset').onchange = applyAssetGate;
  function selectChain(reset = false) {
    const { networks } = ui.portfolioDetails(), config = networks[selected], state = ui.state;
    const network = chainNetwork(selected, state.networks?.[selected]);
    if (reset) { readGeneration++; $('recipient').value = ''; $('amount').value = ''; }
    for (const name of root.querySelectorAll('.selected-network-name')) name.textContent = config.name;
    for (const stage of root.querySelectorAll('.selected-network-stage')) stage.textContent = network.label;
    $('quick-send').disabled = Boolean(config.receiveOnly);
    $('quick-send').title = config.sendNote || '';
    $('quick-earn').hidden = $('quick-swap').hidden = selected !== 'nodus';
    $('send-fields').hidden = Boolean(config.receiveOnly);
    $('send-disabled-note').hidden = !config.receiveOnly;
    $('send-disabled-note').textContent = config.sendNote || 'Sending CPUNK is not available in this release. You can receive to the address above.';
    $('solana-send-hint').hidden = selected !== 'solana' || network.id !== 'mainnet';
    const tokens = config.tokens.filter(() => !isSolanaTron(selected) || network.id === 'mainnet');
    const value = $('asset').value;
    $('asset').replaceChildren(...[{ symbol: config.symbol, tokenId: selected === 'nodus' ? NODUS_TOKEN_ID : undefined, available: true }, ...tokens].map(token => {
      const option = element('option', token.available === false ? `${token.symbol} — Unavailable right now` : token.symbol);
      option.value = token.tokenId || token.symbol; option.dataset.symbol = token.symbol; option.disabled = token.available === false; return option;
    }));
    if ([...$('asset').options].some(option => option.value === value)) $('asset').value = value;
    const address = state.addresses?.[selected === 'cellframe' ? 'cpunk' : selected];
    $('receive-address').textContent = address || '';
    $('receive-qr').replaceChildren();
    if (address) renderQr($('receive-qr'), address);
    $('copy-address').disabled = !address;
    $('quick-receive').disabled = !address;
    const explorers = { ethereum: 'https://etherscan.io/address/', bsc: 'https://bscscan.com/address/', solana: 'https://solscan.io/account/', tron: 'https://tronscan.org/#/address/' };
    const explorer = network.id === 'mainnet' ? explorers[selected] : undefined;
    $('account-explorer').hidden = !explorer || !address;
    if (explorer && address) $('account-explorer').href = explorer + encodeURIComponent(address);
    else $('account-explorer').removeAttribute('href');
    portfolio.setSelected(selected); applyAssetGate(); populateRpc();
    $('history-refresh').disabled = !['nodus', 'solana', 'tron'].includes(selected);
    if (shownPage === 'wallet-activity') void loadHistory();
    updateContractAvailability();
    previousNetwork = JSON.stringify([selected, state.networks?.[selected], selected === 'nodus' ? state.nodus?.state : null]);
    previousTokens = JSON.stringify(selected === 'nodus' ? state.nodus?.tokens : null); previousAddress = address;
  }
  for (const [chain, config] of Object.entries(ui.portfolioDetails().networks)) {
    const option = element('option', config.name); option.value = chain; $('chain').append(option);
  }
  $('chain').value = selected;
  $('chain').onchange = () => { cancelReview(); selected = $('chain').value; selectChain(true); };
  $('copy-address').onclick = () => run(async () => { await window.navigator.clipboard.writeText($('receive-address').textContent); message('Address copied.'); });

  // index.html:116 and src/app.js:1615-1627: the same dialog and decoded rows,
  // including the 600 ms confirmation delay. Only its callbacks change.
  const dialogTemplate = document.createElement('template');
  dialogTemplate.innerHTML = '<dialog id="review-dialog" aria-labelledby="review-title"><h2 id="review-title">Review transfer</h2><p id="review-notice" class="notice">Mainnet transaction. Sending cannot be undone.</p><dl id="review-details"></dl><p id="review-error" role="alert"></p><div class="actions"><button id="cancel-send" class="secondary">Cancel</button><button id="confirm-send" type="button">Confirm &amp; send</button></div></dialog>';
  root.append(dialogTemplate.content.cloneNode(true));
  const cancelPrepared = value => value.chain === 'nodus' ? ui.cancelNodusSend(value.id)
    : isSolanaTron(value.chain) ? ui.cancelSolanaTronSend(value.chain, value.id) : ui.cancelEvmSend(value.id);
  function cancelReview() {
    clearTimeout(reviewTimer);
    if (review) void cancelPrepared(review).catch(() => {});
    review = undefined; if ($('review-dialog').open) $('review-dialog').close();
  }
  $('cancel-send').onclick = cancelReview;
  $('review-dialog').addEventListener('cancel', event => { event.preventDefault(); if (!$('cancel-send').disabled) cancelReview(); });
  $('send-form').onsubmit = event => {
    event.preventDefault();
    if ($('review-button').disabled) return;
    return run(async () => {
      const chain = selected, started = readGeneration;
      const fields = { to: $('recipient').value, amount: $('amount').value };
      const prepared = chain === 'nodus' ? await ui.prepareNodusSend({ ...fields, tokenId: $('asset').value })
        : isSolanaTron(chain) ? await ui.prepareSolanaTronSend({ ...fields, chain, symbol: $('asset').value })
        : await ui.prepareEvmSend({ ...fields, chain, symbol: $('asset').value });
      const value = { ...prepared, chain };
      if (disposed || started !== readGeneration) { await cancelPrepared(value); return; }
      review = value;
      const rows = prepared.review || [['Network', `${CHAINS[chain].name} mainnet`], ['From', ui.state.addresses[chain]], ['To', getAddress(prepared.to)],
        ...(/^0x[0-9a-f]{40}$/.test(prepared.to) ? [['Address check', 'No checksum in what you typed — compare the form above with your source character by character.']] : []),
        ['Asset', prepared.symbol], ['Amount', prepared.amount], ['Network fee', prepared.fee]];
      $('review-details').replaceChildren();
      for (const [key, value] of [...rows, ...(prepared.expiresAt ? [['Review expires', new Date(prepared.expiresAt).toLocaleTimeString()]] : [])]) {
        $('review-details').append(element('dt', key), element('dd', value, ['Address check', 'Name check', 'Timing'].includes(key) ? 'notice' : ''));
      }
      $('review-notice').textContent = `${chainNetwork(chain, ui.state.networks?.[chain]).label} transaction. Sending cannot be undone.`;
      $('review-error').textContent = ''; $('confirm-send').disabled = true; $('cancel-send').disabled = false;
      $('review-dialog').showModal();
      reviewTimer = setTimeout(() => { if (!disposed && review === value) $('confirm-send').disabled = false; }, 600);
    });
  };
  $('confirm-send').onclick = () => {
    if (!review || $('confirm-send').disabled) return;
    $('confirm-send').disabled = $('cancel-send').disabled = true;
    const value = review; review = undefined;
    return run(async () => {
      try {
        const hash = value.chain === 'nodus' ? await ui.confirmNodusSend(value.id)
          : isSolanaTron(value.chain) ? await ui.confirmSolanaTronSend(value.chain, value.id) : await ui.confirmEvmSend(value.id);
        message(`Transaction submitted; confirmation is pending. Transaction ID ${hash}.`);
        await loadBalances(true);
      } catch (error) {
        const note = error.data?.activityTracked ? value.chain === 'nodus'
          ? ' The outcome is tracked in Activity; its coins stay held until it is included or its expiry block passes.'
          : ' A broadcast failure can have an uncertain outcome. Check your address on the chain explorer before creating another transfer.' : '';
        throw new Error(`${error.message}${note}`);
      } finally { if ($('review-dialog').open) $('review-dialog').close(); }
    });
  };

  async function loadHistory(manual = false) {
    const chain = selected, started = ++readGeneration;
    if (!['nodus', 'solana', 'tron'].includes(chain)) {
      $('activity').replaceChildren(); $('history').replaceChildren(); $('history-status').textContent = '';
      root.querySelector('.activity-empty').hidden = true; return;
    }
    if (chain === 'nodus') await ui.loadNodusHistory(); else await ui.loadSolanaTronHistory(chain, { manual });
    if (disposed || started !== readGeneration || selected !== chain) return;
    const detached = element('div'), history = chain === 'nodus' ? ui.state.nodusHistory : ui.state.solanaTronHistory[chain];
    if (chain === 'nodus') renderNodusHistory(document, detached, history, { refresh: () => loadHistory(true), resubmit: hash => run(async () => { await ui.resubmitNodusSend(hash); await loadHistory(); }) });
    else renderSolanaTronHistory(document, detached, { chain, history }, { refresh: () => loadHistory(true) });
    const lists = detached.querySelectorAll('.activity-list');
    $('activity').replaceChildren(...(lists[0]?.children || [])); $('history').replaceChildren(...(lists[1]?.children || []));
    $('history-status').textContent = history?.error || history?.status || '';
    root.querySelector('.activity-empty').hidden = Boolean(history?.local?.length);
  }
  $('history-refresh').onclick = () => run(() => loadHistory(true));
  function renderContracts() {
    if (disposed) return;
    const state = ui.state;
    renderNodusContracts(document, $('evm-root'), { account: state.addresses.nodus, readable: state.nodus?.evmReadable,
      buildable: state.nodus?.evmBuildable, result: contractResult, review: contractReview }, {
      read: fields => run(async () => { const result = await ui.readNodusContract(fields); if (!disposed) { contractResult = result; renderContracts(); } }),
      prepare: fields => run(async () => {
        const value = await ui.prepareNodusContract(fields);
        if (disposed) { await ui.cancelNodusSend(value.id); return; }
        contractReview = value; renderContracts();
      }),
      cancel: () => { if (contractReview) void ui.cancelNodusSend(contractReview.id).catch(() => {}); contractReview = undefined; renderContracts(); },
      confirm: id => run(async () => {
        try { const hash = await ui.confirmNodusSend(id); contractReview = undefined; message(`Transaction submitted; confirmation is pending. Transfer ID ${hash}.`); await loadBalances(true); }
        catch (error) { contractReview = { ...contractReview, error: error.message || 'Sending failed.' }; }
        renderContracts();
      }),
    });
    if (!contractReview) $('evm-root').querySelector('.page-heading')?.remove();
  }
  function updateContractAvailability() {
    const state = ui.state;
    const available = selected === 'nodus' && state.nodus?.state === 'ready' && Boolean(state.nodus?.evmReadable || state.nodus?.evmBuildable);
    $('nav-evm').hidden = $('evm-panel').hidden = !available;
    if (shownPage === 'contracts' && !available) showPage(null);
  }
  // Existing extension-only site grants/recovery reauthentication remain
  // reachable inside Device & settings; vault mutation is still background-owned.
  const settings = element('div');
  renderSettings(document, settings, ui.state, {
    setAutoLock,
    setChainNetwork: (chain, network) => run(() => ui.setChainNetwork(chain, network)),
    selectEvmNetwork: chain => run(() => ui.selectEvmNetwork(chain)),
    setEvmEndpoint: (chain, endpoint) => run(() => ui.setEvmEndpoint(chain, endpoint)),
    discardActivity: () => run(() => ui.discardNodusActivity()), reveal,
  });
  $('auto-lock-minutes').onchange = () => setAutoLock(Number($('auto-lock-minutes').value));
  const recoveryBlock = settings.querySelector('#reveal-password').closest('.page-block');
  recoveryBlock.querySelector('h2').replaceWith(element('h4', 'Reveal recovery phrase'));
  $('device-panel').append(recoveryBlock);
  const connections = element('div', undefined, 'page-block'); $('device-panel').append(connections);
  // Keep the existing selected EVM network and network selectors below the
  // reference's connection disclosure (approved extension plan §5.6).
  for (const [chain, choices] of Object.entries(CHAIN_NETWORKS)) {
    if (choices.length < 2) continue;
    const label = element('label', `${ui.portfolioDetails().networks[chain].name} network`), select = element('select');
    label.htmlFor = select.id = `network-${chain}`;
    for (const choice of choices) { const option = element('option', choice.label); option.value = choice.id; select.append(option); }
    select.onchange = () => run(() => ui.setChainNetwork(chain, select.value)); $('rpc-settings').append(label, select);
  }
  const evmSelect = settings.querySelector('#evm-network');
  if (evmSelect) $('rpc-settings').append(settings.querySelector('label[for="evm-network"]'), evmSelect);
  function populateRpc() {
    const chain = selected, choices = CHAINS[chain]?.rpcOptions || [];
    $('rpc-choice').replaceChildren(...choices.map(provider => { const option = element('option', provider.label); option.value = provider.url; return option; }));
    if (ui.state.evm?.endpoints?.[chain]) $('rpc-choice').value = ui.state.evm.endpoints[chain];
    $('rpc-choice').disabled = $('save-rpc').disabled = !['ethereum', 'bsc'].includes(chain);
  }
  $('save-rpc').onclick = () => run(() => ui.setEvmEndpoint(selected, $('rpc-choice').value));
  $('discard-activity').onclick = () => run(async () => message(await ui.discardNodusActivity() || ''));
  root.querySelector('.device-logs-link a').onclick = event => { event.preventDefault(); navigate('logs'); };
  function update() {
    if (disposed) return;
    const state = ui.state, net = netStatusView(netLevelFor(state.nodus?.state));
    $('net-status').dataset.level = net.level; $('net-status-text').textContent = net.text;
    $('session-timeout').textContent = autoLockBarText(state.preferences.autoLockTimeLimit);
    $('auto-lock-minutes').value = String(state.preferences.autoLockTimeLimit);
    $('wallet-storage-state').textContent = 'Encrypted copy saved in this browser.';
    $('vault-storage-title').textContent = 'Change saved password';
    $('vault-save-explain').textContent = 'This wallet is already saved in this browser. To change its local password, enter your current password and your new password twice, tick the box, then press Change saved password. Your recovery words and wallet addresses stay the same.';
    $('vault-password-controls').hidden = false; $('vault-current-password').hidden = false;
    $('vault-save').hidden = true; $('vault-change').hidden = false;
    $('vault-password-label').textContent = 'New password (at least 16 characters)';
    $('vault-confirm-label').textContent = 'Confirm new password';
    for (const input of $('vault-password-controls').querySelectorAll('input')) input.disabled = true;
    const activityError = state.nodus?.activityError || (state.nodus?.quarantinedCount ? `${state.nodus.quarantinedCount} saved records could not be read; their coins stay held.` : '');
    $('vault-status').textContent = activityError; $('discard-activity').hidden = !activityError;
    const tokens = JSON.stringify(selected === 'nodus' ? state.nodus?.tokens : null), address = state.addresses?.[selected === 'cellframe' ? 'cpunk' : selected];
    const identity = JSON.stringify([selected, state.networks?.[selected], selected === 'nodus' ? state.nodus?.state : null]);
    if (identity !== previousNetwork || tokens !== previousTokens || address !== previousAddress) {
      if (previousNetwork && identity !== previousNetwork) { readGeneration++; cancelReview(); }
      previousNetwork = identity; previousTokens = tokens; previousAddress = address; selectChain();
    }
    for (const chain of ['solana', 'tron']) $(`network-${chain}`).value = chainNetwork(chain, state.networks?.[chain]).id;
    if (evmSelect) evmSelect.value = state.evm.selectedChain;
    updateContractAvailability();
    renderSites(document, connections, state, origin => run(() => ui.revoke(origin)));
    portfolio.update();
  }
  const clock = setInterval(() => portfolio.update(), 30000);
  update(); route();
  return {
    update,
    dispose() { disposed = true; readGeneration++; cancelReview(); if (contractReview) void ui.cancelNodusSend(contractReview.id).catch(() => {}); clearInterval(clock); window.removeEventListener('hashchange', route); root.after(status); },
  };
}
