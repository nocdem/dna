import { WALLET_MARKUP } from './wallet-markup.js';
import { createPortfolio } from '../../../src/portfolio-view.js';
import { CHAINS, CELLFRAME } from '../../../src/config.js';
import { CPUNK_ASSET } from '../../../src/portfolio.js';
import { NODUS_TOKEN_ID, NODUS_ASSET, nodusNetworkFor } from '../../../src/nodus/network.js';
import { IXIOS_NETWORK, IXIOS_ASSET } from '../../../src/ixios/network.js';
import { portfolioReaders, mountSavedSettings, mountDeleteWallet } from './wallet-page.js';
import { readBalanceRefresh, writeBalanceRefresh, balanceRefreshNote } from '../../../src/balance-refresh.js';
import { readShowZero, writeShowZero, showZeroNote } from '../../../src/zero-balances.js';
import { sessionLog, mountSessionLogView, LOG_FILTERS, dateTimeText } from '../../../src/session-log.js';
import { extensionAutoLockNote } from './wallet-ui.js';
import { mountAddressBook } from './address-book-page.js';
import { mountEarn } from './earn-page.js';
import { mountNameBlock } from './name-block.js';
import { mountClaimAction } from './claim-action.js';
import { mountContractsPage } from './contracts-page.js';
import { mountVaultsPage } from './vaults-page.js';
import { appIcon } from './presentation.js';
import { autoLockBarText } from '../../../src/auto-lock.js';
import { netLevelFor, netStatusView } from '../../../src/net-status.js';
import { renderQr } from '../../../src/qr.js';
import { CHAIN_NETWORKS, chainNetwork } from '../constants/networks.js';
import { renderSites, renderSettings } from './views.js';
import { renderNodusHistory } from './nodus-screens.js';
import { renderSolanaTronHistory } from './solana-tron-screens.js';

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
  $('activity-panel').querySelector('.page-block .hint').textContent = 'Sends made in this wallet, tracked until final. Once confirmed, a send is listed under Account history where this network’s history is read. Records are saved encrypted in this browser.';
  // Approved extension plan §3.6: the extension-only connected-sites page.
  const sitesPage = element('div', undefined, 'wallet-page'); sitesPage.id = 'page-sites'; sitesPage.dataset.page = 'sites'; sitesPage.hidden = true;
  const sitesBack = element('button', '← Back to wallet', 'secondary small page-back'); sitesBack.type = 'button';
  const connections = element('section', undefined, 'dashboard-panel'); sitesPage.append(sitesBack, connections); $('wallet-open').append(sitesPage);
  const sitesLink = element('a'); sitesLink.href = '#sites'; sitesLink.dataset.hint = 'Sites permitted to connect'; sitesLink.append(appIcon(document, 'sites'), element('span', 'Connected sites', 'nav-name')); root.querySelector('.wallet-navigation').append(sitesLink);
  let selected = 'nodus', shownPage = null, disposed = false, readGeneration = 0, review, reviewTimer;
  let previousNetwork, previousTokens, previousAddress, walletScroll = 0, backgroundLog = { entries: [], running: [] };
  const networkVersions = new Map(), endpointVersions = new Map(), logSubscriptions = [];
  let book, earn, names, claim, contracts, vaults;
  const isSolanaTron = chain => chain === 'solana' || chain === 'tron';
  const selectedNetwork = chain => chain === 'ixios' ? { id: 'mainnet', label: 'Mainnet', endpoint: IXIOS_NETWORK.endpoint } : chainNetwork(chain, ui.state.networks?.[chain]);
  function element(tag, text, className = '') {
    const node = document.createElement(tag); node.className = className;
    if (text !== undefined) node.textContent = text; return node;
  }
  const message = text => { status.textContent = text; status.className = 'result'; sessionLog.log('wallet', text); };
  const networkDefinitions = () => ({ nodus: nodusNetworkFor(ui.state.nodus?.state === 'ready', { module: true, tokens: ui.state.nodus?.tokens }), ...CHAINS, cellframe: CELLFRAME,
    // Background derivations have settled before unlock is published. Without
    // an Ixios address there is no balance source for this session; use the
    // shared portfolio's unavailable-source branch (portfolio-view.js:78-85).
    ixios: ui.state.addresses.ixios ? IXIOS_NETWORK : { ...IXIOS_NETWORK, balanceUnavailable: true } });
  let networks = networkDefinitions(), latestKept = {}, opened = false;
  const readers = portfolioReaders(ui);
  const portfolio = createPortfolio({ ...readers, selectAsset,
    async readBalances(chain, ...args) {
      const rows = await readers.readBalances(chain, ...args);
      // src/app.js syncNodusPins: a balance read can change pin availability.
      // Read only public state, then preserve this read when its keys match.
      if (chain === 'nodus') { await ui.refresh(); if (!disposed && ui.state.isUnlocked) update(); }
      return rows;
    },
    leadingNetworks: [{ network: networks.nodus, asset: NODUS_ASSET }],
    extraNetworks: [{ network: CELLFRAME, asset: CPUNK_ASSET }, { network: networks.ixios, asset: IXIOS_ASSET }],
    onKept(entries) {
      latestKept = Object.fromEntries(Object.entries(entries).filter(([key]) => !['solana', 'tron'].includes(key.split(':')[0]) || ui.state.networks?.[key.split(':')[0]] === 'mainnet'));
      void ui.request('keepBalances', [latestKept]).catch(error => sessionLog.log('wallet', error, { error: true }));
    } });
  let deviceStorage; try { deviceStorage = window.localStorage; } catch { /* device preferences stay in this page */ }
  const applyRefresh = minutes => { $('balance-refresh-minutes').value = String(minutes); portfolio.setAutoRefresh(minutes); return balanceRefreshNote(minutes); };
  $('balance-refresh-note').textContent = applyRefresh(readBalanceRefresh(deviceStorage));
  $('balance-refresh-minutes').onchange = () => { const minutes = Number($('balance-refresh-minutes').value), kept = writeBalanceRefresh(deviceStorage, minutes); $('balance-refresh-note').textContent = applyRefresh(minutes) + (kept ? '' : ' This browser did not allow saving the choice: it applies until this page is closed.'); };
  const applyZero = show => { $('show-zero-balances').checked = show; portfolio.setHideZero(!show); return showZeroNote(show); };
  $('show-zero-balances-note').textContent = applyZero(readShowZero(deviceStorage));
  $('show-zero-balances').onchange = () => { const show = $('show-zero-balances').checked, kept = writeShowZero(deviceStorage, show); $('show-zero-balances-note').textContent = applyZero(show) + (kept ? '' : ' This browser did not allow saving the choice: it applies until this page is closed.'); };
  const initial = ui.request('getKeptBalances').catch(() => ({})).then(entries => {
    if (disposed) return;
    latestKept = Object.fromEntries(Object.entries(entries).filter(([key]) => !['solana', 'tron'].includes(key.split(':')[0]) || ui.state.networks?.[key.split(':')[0]] === 'mainnet'));
    const kept = Object.fromEntries(Object.entries(latestKept).map(([key, value]) => [key, { ...value, units: BigInt(value.units) }]));
    portfolio.open(publicAddresses(), endpoints(), { kept, automatic: false }); opened = true;
    earn?.update(); void claim?.refresh();
    return portfolio.refresh();
  });
  const publicAddresses = () => ({ ...ui.state.addresses, cellframe: ui.state.addresses.cpunk });
  function endpoints() { return Object.fromEntries(Object.entries(networks).map(([chain, config]) => [chain, ui.state.evm?.endpoints?.[chain] || selectedNetwork(chain).endpoint || config.endpoint])); }
  const ixiosStatus = element('p', '', 'hint'); ixiosStatus.id = 'ixios-address-status'; ixiosStatus.setAttribute('role', 'status'); ixiosStatus.setAttribute('aria-live', 'polite'); $('cellframe-address-status').after(ixiosStatus);
  $('lock').onclick = lock;

  // src/app.js:2083-2251: pages replace wallet-home, while both shortcuts lead
  // to the same, persistent Send / Receive panel. Hashes use the web names.
  function showPage(name, { focus = true } = {}) {
    const candidate = [...root.querySelectorAll('.wallet-page')].find(page => page.dataset.page === name);
    const page = candidate && !candidate.querySelector('.dashboard-panel').hidden ? candidate : null;
    const previous = shownPage;
    if (page && !previous) walletScroll = window.scrollY;
    if (shownPage === 'settings' && name !== 'settings') clearReveal();
    shownPage = page ? name : null;
    $('wallet-home').hidden = Boolean(page);
    for (const node of root.querySelectorAll('.wallet-page')) node.hidden = node !== page;
    if (page) {
      root.querySelector('.wallet-card').scrollIntoView({ block: 'start' });
      if (focus) { const heading = page.querySelector('h3, h1'); if (heading) { heading.tabIndex = -1; heading.focus({ preventScroll: true }); } }
    } else if (previous) window.scrollTo(0, walletScroll);
    if (name === 'wallet-activity') void loadHistory();
    if (name === 'earn') void earn.refresh();
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
    if (action === 'earn') { navigate('earn'); return; }
    navigate(null);
    if (action === 'send' || action === 'receive') $(action === 'send' ? 'quick-send' : 'quick-receive').click();
    else if (window.matchMedia('(max-width: 900px)').matches) $('send-form').scrollIntoView({ block: 'start' });
  }
  function applyAssetGate() {
    const option = $('asset').selectedOptions[0];
    $('review-button').disabled = !option || option.disabled || networks[selected].receiveOnly;
  }
  $('asset').onchange = applyAssetGate;
  function selectChain(reset = false) {
    const config = networks[selected], state = ui.state;
    const network = selectedNetwork(selected);
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
    $('history-refresh').disabled = !['nodus', 'ethereum', 'solana', 'tron', 'cellframe'].includes(selected);
    if (shownPage === 'wallet-activity') void loadHistory();
    updateContractAvailability();
    book?.update(); earn?.update(); names?.update();
    previousNetwork = JSON.stringify([selected, state.networks?.[selected], selected === 'nodus' ? state.nodus?.state : null]);
    previousTokens = JSON.stringify(selected === 'nodus' ? state.nodus?.tokens : null); previousAddress = address;
  }
  for (const [chain, config] of Object.entries(networks)) {
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
  function showPrepared(prepared, { chain = 'nodus', title = 'Review transfer' } = {}) {
    cancelReview();
    if (chain === 'nodus' && selected !== 'nodus') { selected = 'nodus'; $('chain').value = selected; selectChain(); }
    const value = { ...prepared, chain }; review = value;
    const rows = prepared.review || [];
    $('review-title').textContent = title;
    $('review-details').replaceChildren();
    const expires = prepared.expiresAt && !rows.some(([key]) => key === 'Review expires') ? [['Review expires', new Date(prepared.expiresAt).toLocaleTimeString()]] : [];
    for (const [key, text] of [...rows, ...expires]) $('review-details').append(element('dt', key), element('dd', text, ['Address check', 'Name check', 'Timing'].includes(key) ? 'notice' : ''));
    $('review-notice').textContent = `${selectedNetwork(chain).label} transaction. Sending cannot be undone.`;
    const confirmText = { claim: 'Confirm & claim', delegate: 'Confirm & delegate', undelegate: 'Confirm & undelegate', stake: 'Confirm & bond', name: 'Confirm & register' };
    $('confirm-send').textContent = confirmText[value.kind] || 'Confirm & send';
    $('review-error').textContent = ''; $('confirm-send').disabled = true; $('cancel-send').disabled = false;
    $('review-dialog').showModal();
    reviewTimer = setTimeout(() => { if (!disposed && review === value) $('confirm-send').disabled = false; }, 600);
  }
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
      showPrepared(prepared, { chain });
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
        if (!value.kind) { book.offer(value.chain, value.to, value.named?.name || value.recipientName); $('recipient').value = $('amount').value = ''; }
        if (['delegate', 'undelegate', 'stake'].includes(value.kind)) earn.sent();
        if (value.kind === 'name') names.sent();
        if (value.kind === 'claim') void claim.refresh();
        await loadBalances(true);
      } catch (error) {
        const note = error.data?.activityTracked ? value.chain === 'nodus'
          ? ' The outcome is tracked in Activity; its coins stay held until it is included or its expiry block passes.'
          : ' A broadcast failure can have an uncertain outcome. Check your address on the chain explorer before creating another transfer.' : '';
        throw new Error(`${error.message}${note}`);
      } finally { if ($('review-dialog').open) $('review-dialog').close(); if (value.chain === 'nodus') void claim.refresh(); }
    });
  };

  async function loadHistory(manual = false) {
    const chain = selected, started = ++readGeneration;
    if (!['nodus', 'ethereum', 'bsc', 'solana', 'tron', 'cellframe'].includes(chain)) {
      $('activity').replaceChildren(); $('history').replaceChildren(); $('history-status').textContent = '';
      root.querySelector('.activity-empty').hidden = true; return;
    }
    let history;
    if (chain === 'nodus') { await ui.loadNodusHistory(); history = ui.state.nodusHistory; }
    else if (isSolanaTron(chain)) { await ui.loadSolanaTronHistory(chain, { manual }); history = ui.state.solanaTronHistory[chain]; }
    else if (chain === 'bsc') history = { rows: [], local: await ui.request('getChainLocalHistory', [chain]), status: 'Account history for BNB Smart Chain is not read here. Use the account explorer.' };
    else history = await ui.request('getChainHistory', [chain, { manual }]);
    if (disposed || started !== readGeneration || selected !== chain) return;
    const detached = element('div');
    if (chain === 'nodus') renderNodusHistory(document, detached, history, { refresh: () => loadHistory(true), resubmit: hash => run(async () => { await ui.resubmitNodusSend(hash); await loadHistory(); }) });
    else renderSolanaTronHistory(document, detached, { chain, history }, { refresh: () => loadHistory(true),
      abandon: hash => run(async () => { await ui.request('abandonActivity', [chain, hash]); await loadHistory(); }) });
    const lists = detached.querySelectorAll('.activity-list');
    $('activity').replaceChildren(...(lists[0]?.children || [])); $('history').replaceChildren(...(lists[1]?.children || []));
    $('history-status').textContent = history?.error || history?.status || '';
    root.querySelector('.activity-empty').hidden = Boolean(history?.local?.length);
  }
  $('history-refresh').onclick = () => run(() => loadHistory(true));
  book = mountAddressBook({ root, document, ui, networks, selected: () => selected, navigate, run });
  earn = mountEarn({ root, document, ui, selected: () => selected, portfolio, run, showReview: showPrepared, navigate });
  names = mountNameBlock({ root, ui, selected: () => selected, run, showReview: showPrepared });
  claim = mountClaimAction({ ui, portfolio, run, showReview: showPrepared });
  contracts = mountContractsPage({ rootNode: $('evm-root'), panelNode: $('evm-panel'), ui });
  vaults = mountVaultsPage({ rootNode: $('vaults-root'), panelNode: $('vault-panel'), ui });
  mountSavedSettings({ root, ui, run }); mountDeleteWallet({ root, document, ui, run, status });
  const mergedLog = {
    entries(filter = 'all') { return [...sessionLog.entries(filter), ...backgroundLog.entries.filter(LOG_FILTERS[filter] || LOG_FILTERS.all)].sort((a, b) => a.at - b.at); },
    running(filter = 'all') { return [...sessionLog.running(filter), ...backgroundLog.running.filter(LOG_FILTERS[filter] || LOG_FILTERS.all)].sort((a, b) => a.at - b.at); },
    subscribe(listener) { const stop = sessionLog.subscribe(listener); logSubscriptions.push(stop); return stop; },
    exportText(options) {
      const header = sessionLog.exportText(options).split('\n').slice(0, 7).join('\n');
      const lines = [...this.entries(), ...this.running()].sort((a, b) => a.at - b.at).map(line => `${dateTimeText(line.at)} [${line.category}]${line.error ? ' !' : ''} ${line.text}`);
      return `${header}\n\n${lines.join('\n') || '(no entries)'}\n`;
    } };
  mountSessionLogView({ panel: $('session-logs'), filter: $('session-log-filter'), output: $('session-log-text'), copy: $('session-log-copy'), download: $('session-log-download'), status: $('session-log-status') },
    { log: mergedLog, version: globalThis.chrome?.runtime?.getManifest?.().version || 'unknown' });
  async function readBackgroundLog() { try { const value = await ui.request('getSessionLog'); if (!disposed) backgroundLog = value; } catch { /* the next visible read retries */ } }
  const logClock = setInterval(() => { if ($('session-logs').open && !document.hidden) void readBackgroundLog(); }, 1000);
  const resume = () => { if (!document.hidden) void ui.request('checkNodusLiveness').catch(error => sessionLog.log('net', error, { error: true })); };
  window.addEventListener('online', resume); window.addEventListener('pageshow', resume); document.addEventListener('visibilitychange', resume);
  void readBackgroundLog();
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
  // Keep the existing selected EVM network and network selectors below the
  // reference's connection disclosure (approved extension plan §5.6).
  for (const [chain, choices] of Object.entries(CHAIN_NETWORKS)) {
    if (choices.length < 2) continue;
    const label = element('label', `${networks[chain].name} network`), select = element('select');
    label.htmlFor = select.id = `network-${chain}`;
    for (const choice of choices) { const option = element('option', choice.label); option.value = choice.id; select.append(option); }
    select.onchange = () => run(async () => { await ui.request('setChainNetwork', [chain, select.value]); await ui.refresh(); }); $('rpc-settings').append(label, select);
  }
  const evmSelect = settings.querySelector('#evm-network');
  if (evmSelect) $('rpc-settings').append(settings.querySelector('label[for="evm-network"]'), evmSelect);
  function populateRpc() {
    const chain = selected, choices = CHAINS[chain]?.rpcOptions || [];
    $('rpc-choice').replaceChildren(...choices.map(provider => { const option = element('option', provider.label); option.value = provider.url; return option; }));
    const enabled = ['ethereum', 'bsc'].includes(chain);
    $('rpc-settings').hidden = false;
    for (const node of [$('rpc-choice'), $('save-rpc'), $('rpc-settings').querySelector('label[for="rpc-choice"]')]) node.hidden = !enabled;
    if (enabled) {
      const custom = element('option', 'Custom HTTPS endpoint…'); custom.value = 'custom'; $('rpc-choice').append(custom);
      const endpoint = ui.state.evm?.endpoints?.[chain] || CHAINS[chain].endpoint;
      $('rpc-choice').value = choices.some(choice => choice.url === endpoint) ? endpoint : 'custom'; $('rpc-endpoint').value = endpoint;
    }
    showCustomRpc();
    if (!enabled) $('rpc-endpoint').hidden = $('rpc-endpoint-label').hidden = true;
  }
  function showCustomRpc() { $('rpc-endpoint').hidden = $('rpc-endpoint-label').hidden = $('rpc-choice').value !== 'custom'; }
  $('rpc-choice').onchange = showCustomRpc;
  $('save-rpc').onclick = () => run(() => ui.setEvmEndpoint(selected, $('rpc-choice').value === 'custom' ? $('rpc-endpoint').value : $('rpc-choice').value));
  $('discard-activity').onclick = () => run(async () => message(await ui.discardNodusActivity() || ''));
  root.querySelector('.device-logs-link a').onclick = event => { event.preventDefault(); navigate('logs'); };
  function update() {
    if (disposed) return;
    const state = ui.state, net = netStatusView(netLevelFor(state.nodus?.state));
    networks = networkDefinitions();
    for (const [chain, config] of Object.entries(networks)) {
      const testnet = ['solana', 'tron'].includes(chain) && selectedNetwork(chain).id !== 'mainnet';
      const endpoint = endpoints()[chain], previousEndpoint = endpointVersions.get(chain);
      const version = JSON.stringify([config, testnet, endpoint]);
      if (networkVersions.get(chain) !== version) {
        const before = networkVersions.get(chain); networkVersions.set(chain, version);
        endpointVersions.set(chain, endpoint);
        portfolio.setNetwork(chain, { ...config, testnet }, { keepRead: !before || chain === 'nodus' });
        if (opened && before && previousEndpoint !== endpoint) portfolio.changeEndpoint(chain, endpoint);
        if (opened) portfolio.setAddress(chain, publicAddresses()[chain]);
      }
    }
    $('net-status').dataset.level = net.level; $('net-status-text').textContent = net.text;
    $('session-timeout').textContent = autoLockBarText(state.preferences.autoLockTimeLimit);
    $('auto-lock-minutes').value = String(state.preferences.autoLockTimeLimit);
    $('auto-lock-note').textContent = extensionAutoLockNote(state.preferences.autoLockTimeLimit);
    $('wallet-storage-state').textContent = 'Encrypted copy saved in this browser.';
    $('vault-storage-title').textContent = 'Change saved password';
    $('vault-save-explain').textContent = 'This wallet is already saved in this browser. To change its local password, enter your current password and your new password twice, tick the box, then press Change saved password. Your recovery words and wallet addresses stay the same.';
    $('vault-password-controls').hidden = false; $('vault-current-password').hidden = false;
    $('vault-save').hidden = true; $('vault-change').hidden = false;
    $('vault-password-label').textContent = 'New password (at least 16 characters)';
    $('vault-confirm-label').textContent = 'Confirm new password';
    for (const chain of ['nodus', 'cellframe', 'ixios']) {
      const node = $(`${chain}-address-status`); node.hidden = selected !== chain;
      node.textContent = publicAddresses()[chain] ? 'Derived locally from this wallet’s recovery phrase.' : chain === 'ixios' ? 'Ixios address unavailable. Lock and reopen your wallet to retry.' : '';
    }
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
    book.update(); earn.update(); names.update(); claim.update(); contracts.update(); vaults.update();
    if (shownPage && root.querySelector(`.wallet-page[data-page="${shownPage}"] .dashboard-panel`)?.hidden) navigate(null);
    renderSites(document, connections, state, origin => run(() => ui.revoke(origin)));
  }
  update(); route();
  return {
    update,
    async loadBalances(force = false) { await initial; if (force && !disposed) await portfolio.refresh(); },
    dispose() {
      disposed = true; readGeneration++; cancelReview(); portfolio.setAutoRefresh(0); portfolio.clear();
      book.dispose(); earn.dispose(); names.dispose(); claim.dispose(); contracts.dispose(); vaults.dispose();
      $('session-logs').open = false; logSubscriptions.forEach(stop => stop()); clearInterval(logClock);
      window.removeEventListener('online', resume); window.removeEventListener('pageshow', resume); document.removeEventListener('visibilitychange', resume);
      window.removeEventListener('hashchange', route); root.after(status);
    },
  };
}
