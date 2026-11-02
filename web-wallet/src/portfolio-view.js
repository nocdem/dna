import { groupNetworkEntries } from './network-groups.js';
import { capabilitiesFor } from './capabilities.js';
import { CHAINS } from './config.js';
import { PQ_NETWORKS } from './pq/networks.js';
import { ASSETS, chainBalances, balanceErrorDetail, unavailableBalanceLabel, holdingActions, sameAssetKeys, readPrices as defaultReadPrices, portfolioSnapshot, groupNetworks, usdText, displayAmount } from './portfolio.js';

const names = { ETH: 'Ethereum', BNB: 'BNB', SOL: 'Solana', TRX: 'TRON', USDT: 'Tether', USDC: 'USD Coin', DAI: 'Dai', USDD: 'USDD', CPUNK: 'CPUNK' };
// Asset symbol -> its own icon file. Keyed by symbol, not guessed from it, so an
// asset can carry a different file extension/name than its lowercase symbol
// (CPUNK's icon is a PNG, not a same-named SVG).
const icons = { ETH: 'eth.svg', BNB: 'bnb.svg', SOL: 'sol.svg', TRX: 'trx.svg', USDT: 'usdt.svg', CPUNK: 'cpunk.png' };
const $ = id => document.getElementById(id);
function el(tag, className, text) { const node = document.createElement(tag); node.className = className; if (text !== undefined) node.textContent = text; return node; }
// The coin and network icons are part of the build (src/assets/coins), so
// they get content-hashed names that the sites cache for a year (0.1.102).
// Served from public/assets/coins under a fixed name they were "no-store"
// (the sites cache only content-hashed files, nginx 2026-10-12), and every
// redraw of the list fetched each icon again: they blinked out until loaded.
// Each file is named here so the build emits only what it uses: Ixios's icon
// only in a build with Ixios on (a build without it carries no Ixios code or
// file, test/browser-ixios.js). Small files are inlined as data: URLs (CSP
// img-src allows data:); `data-icon` keeps the file name for tests.
const ICON_URLS = {
  'algorand.png': new URL('./assets/coins/algorand.png', import.meta.url).href,
  'tidecoin.svg': new URL('./assets/coins/tidecoin.svg', import.meta.url).href,
  'ckb.png': new URL('./assets/coins/ckb.png', import.meta.url).href,
  'soqucoin.png': new URL('./assets/coins/soqucoin.png', import.meta.url).href,
  'qtc.svg': new URL('./assets/coins/qtc.svg', import.meta.url).href,
  'verona.svg': new URL('./assets/coins/verona.svg', import.meta.url).href,
  'splendor.svg': new URL('./assets/coins/splendor.svg', import.meta.url).href,
  'asentum.png': new URL('./assets/coins/asentum.png', import.meta.url).href,
  'bnb.svg': new URL('./assets/coins/bnb.svg', import.meta.url).href,
  'cellframe.svg': new URL('./assets/coins/cellframe.svg', import.meta.url).href,
  'cpunk.png': new URL('./assets/coins/cpunk.png', import.meta.url).href,
  'eth.svg': new URL('./assets/coins/eth.svg', import.meta.url).href,
  'nodus.svg': new URL('./assets/coins/nodus.svg', import.meta.url).href,
  'sol.svg': new URL('./assets/coins/sol.svg', import.meta.url).href,
  'trx.svg': new URL('./assets/coins/trx.svg', import.meta.url).href,
  'usdt.svg': new URL('./assets/coins/usdt.svg', import.meta.url).href,
  ...(import.meta.env.VITE_ENABLE_IXIOS === 'true' ? { 'ixios.png': new URL('./assets/coins/ixios.png', import.meta.url).href } : {})
};
const PQ_ICONS = new Set(Object.values(PQ_NETWORKS).map(network => network.icon));
function iconImg(file) { const img = el('img', PQ_ICONS.has(file) ? 'coin-icon pq-coin-icon' : 'coin-icon'); img.src = ICON_URLS[file]; img.dataset.icon = file; img.alt = ''; img.width = 36; img.height = 36; return img; }
// `network`, when given, is the network the asset group belongs to: an optional
// network's own asset that has no entry in `icons` (and whose symbol is that
// network's own symbol) shows the network's icon rather than a letter.
function icon(symbol, network) {
  const file = icons[symbol] || (network?.symbol === symbol ? network.icon : undefined);
  if (!file) return el('span', 'coin-icon coin-letter', symbol === 'USDC' ? '$' : symbol[0]);
  return iconImg(file);
}
// A network's own icon (from config.js) takes priority over its symbol's asset
// icon: Cellframe's network symbol is CPUNK, but its network identity (the
// health badge, the per-chain holding row) must show the Cellframe logo, not
// the CPUNK asset icon shown in the asset summary.
function networkIcon(c) { return c.icon ? iconImg(c.icon) : icon(c.symbol); }

function groupedNetworkControls(entries, control, expanded) {
  return groupNetworkEntries(entries).map(group => {
    const block = el('div', 'network-group'), items = el('div', 'network-group-items');
    block.dataset.networkGroup = group.id;
    block.setAttribute('role', 'group'); block.setAttribute('aria-label', group.label);
    items.append(...group.entries.map(control));
    const title = el('h4', 'network-group-title');
    if (group.id === 'pq' || group.id === 'legacy') {
      const button = el('button', 'network-group-toggle', group.label); button.type = 'button';
      const count = group.entries.length;
      button.setAttribute('aria-label', `${group.label}, ${count} ${count === 1 ? 'network' : 'networks'}`);
      const badge = el('span', 'network-group-count', String(count)); badge.setAttribute('aria-hidden', 'true'); button.append(badge);
      button.dataset.networkGroupToggle = group.id; items.id = `portfolio-network-group-${group.id}`;
      button.setAttribute('aria-controls', items.id);
      const update = () => { const open = expanded.has(group.id); button.setAttribute('aria-expanded', String(open)); items.hidden = !open; };
      const symbol = el('span', 'network-group-symbol'); symbol.setAttribute('aria-hidden', 'true'); button.append(symbol);
      button.onclick = () => { if (expanded.has(group.id)) expanded.delete(group.id); else expanded.add(group.id); update(); };
      update(); title.append(button);
    } else title.textContent = group.label;
    block.append(title, items);
    return block;
  });
}

// This controller receives only public addresses, never a wallet or signing key.
// `extraNetworks` is an ordered list of `{ network: { name, symbol, receiveOnly,
// ... }, asset }` entries (Cellframe/CPUNK_ASSET, and Ixios/IXIOS_ASSET when its
// build flag is on): unpriced, receive-only networks merged after the permanent
// CHAINS/ASSETS registry, all handled the same way. Their addresses are derived
// later than the others (asynchronous local derivation, not part of
// deriveWallet()), so their balance reads are not started at open() alongside
// the rest; a read starts once setAddress() reports the derived address, or the
// row is marked errored if derivation fails.
// `leadingNetworks` has the same shape but is placed before CHAINS (Nodus, the
// wallet's native network, listed first in badges and filters). A network with
// `balanceUnavailable` has no balance source yet: its assets are flagged so
// portfolioSnapshot() reports them 'unsupported', and its chain is left out of
// `chains`, so readBalances is never called for it.
// `onKept(entries)`: called after every successful read with the last balance
// per asset — { assetKey: { units (decimal string), observedAt (ms), address } }
// — so the app can save it with a saved wallet; open(…, { kept }) shows such
// entries until a fresh read replaces them.
export function createPortfolio({ readBalances, readPrices = defaultReadPrices, selectAsset, leadingNetworks = [], extraNetworks = [], onKept }) {
  const entries = (list) => Object.fromEntries(list.map(({ network, asset }) => [asset.chain, network]));
  const networks = { ...entries(leadingNetworks), ...CHAINS, ...entries(extraNetworks) };
  const baseAssets = [...leadingNetworks.map(({ asset }) => asset), ...ASSETS, ...extraNetworks.map(({ asset }) => asset)];
  let assets, chains;
  // A leading network's own tokens (NODUS: the pinned tokens its send module
  // reports while ready — network.tokens, src/nodus/network.js nodusTokens;
  // design docs/plans/2026-10-22-connect-native-tokens-design.md §6) are rows
  // of that network, listed right after its own asset. Unpriced like the
  // network's asset (no priceId), keyed `chain:SYMBOL`.
  const tokenAssets = chain => (networks[chain].tokens || []).map(t => ({ chain, symbol: t.symbol, decimals: t.decimals, tokenId: t.tokenId, key: `${chain}:${t.symbol}` }));
  const leadingAssets = new Set(leadingNetworks.map(({ asset }) => asset));
  // Re-derived when setNetwork() swaps a network (NODUS while its send module
  // is ready, src/nodus/network.js nodusNetworkFor).
  function flag() {
    assets = baseAssets.flatMap(asset => [asset, ...(leadingAssets.has(asset) ? tokenAssets(asset.chain) : [])])
      // Extension test networks have no configured token deployments and no
      // USD price identity (operator 2026-10-29, plan row 21).
      .filter(asset => !networks[asset.chain].testnet || asset.symbol === networks[asset.chain].symbol)
      .map(asset => { if (!networks[asset.chain].testnet) return asset; const { priceId, ...unpriced } = asset; return unpriced; })
      .map(asset => networks[asset.chain].balanceUnavailable ? { ...asset, balanceUnavailable: true } : asset);
    chains = Object.keys(networks).filter(chain => !networks[chain].balanceUnavailable);
  }
  flag();
  // `selected`: the network chosen in the Send / Receive panel, set by the app
  // through setSelected(). It is UI state, not wallet state, so clear() keeps it.
  let addresses, endpoints, balances = {}, quotes = {}, filter = 'all', hidden = false, session = 0, timer, priceJob, selected;
  // Zero balances left out of the list (src/zero-balances.js; src/app.js sets
  // it from Device & settings).
  let hideZero = true;
  // Automatic updates (src/balance-refresh.js, 0.1.93): every `autoMinutes`
  // while the page is shown (0 = off); `readAt` the start of the last full
  // read, `pricesAt` of the last price read, `doneAt` when the last full read
  // finished (those three cleared with the wallet). `autoMinutes` is kept
  // across open()/clear() (a device setting, like `selected`).
  let autoMinutes = 0, autoTimer, readAt = 0, pricesAt = 0, doneAt = 0;
  // assetKey -> { units: bigint, observedAt, address }: the last balance read.
  let kept = {};
  function keepRead(chain, result) {
    for (const [key, value] of Object.entries(result)) if (value.state === 'ready') kept[key] = { units: value.units, observedAt: value.observedAt, address: addresses[chain] };
    onKept?.(Object.fromEntries(Object.entries(kept).map(([key, k]) => [key, { units: k.units.toString(), observedAt: k.observedAt, address: k.address }])));
  }
  // One extra action per network, shown under that network's asset group
  // (today only NODUS: "Claim your allocation", src/app.js refreshClaim).
  // `{ label, note, run }`; cleared by clear() and setAction(chain, undefined).
  let rowActions = {};
  const expandedNetworkGroups = new Set();
  const expandedAssets = new Set();
  const receiveActions = el('div', 'receive-network-actions'); receiveActions.id = 'receive-network-actions';
  $('receive-panel').append(receiveActions);
  function renderReceiveActions() {
    const focused = document.activeElement?.dataset?.rowAction;
    receiveActions.replaceChildren(...Object.entries(rowActions[selected] || {}).map(([id, action]) => {
      const block = el('div', 'asset-action notice'), button = el('button', 'small', action.label); button.type = 'button'; button.dataset.rowAction = id === 'main' ? selected : `${selected}:${id}`;
      button.onclick = () => action.run(button); block.append(el('p', '', action.note), button); return block;
    }));
    if (focused) [...receiveActions.querySelectorAll('button')].find(button => button.dataset.rowAction === focused)?.focus({ preventScroll: true });
  }
  // Networks whose rows also offer "Earn" (today only NODUS, while the app's
  // staking panel is shown: src/app.js setEarnAvailable). Cleared by clear().
  let earn = {};
  const jobs = new Map();
  const text = value => hidden ? '••••' : value;
  // The last balance read per asset of THIS wallet's addresses (kept below);
  // only an entry whose address is the one shown now is used.
  function visibleKept() {
    if (!addresses) return {};
    return Object.fromEntries(Object.entries(kept).filter(([key, k]) => addresses[key.split(':')[0]] === k.address));
  }
  const readTime = ms => new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  function render() {
    // Read again automatically: a balance counts until two minutes past its
    // next scheduled read, so a value is never crossed out between reads.
    const snap = portfolioSnapshot(balances, quotes, Date.now(), assets, visibleKept(), { balanceMaxAge: autoMinutes ? (autoMinutes + 2) * 60000 : 0 });
    $('portfolio-total').textContent = text(usdText(snap.total, snap.positive));
    $('portfolio-label').textContent = snap.state === 'partial' ? 'Known value · incomplete' : snap.state === 'loading' ? 'Updating portfolio' : 'Estimated portfolio value';
    $('portfolio-status').textContent = snap.state === 'idle' ? 'Refresh all to read your balances and prices.'
      : snap.state === 'loading' ? `${snap.known} of ${assets.filter(asset => asset.priceId).length} asset values available. Reading all networks…`
      : snap.complete ? 'All supported asset balances are included.'
      : `${snap.missingBalances} balances and ${snap.missingPrices} prices unavailable or out of date. Missing values are excluded.`;
    $('portfolio-refresh').disabled = jobs.size > 0 || !!priceJob;
    $('refresh').disabled = jobs.size > 0 || !!priceJob;
    $('portfolio-hide').textContent = hidden ? 'Show balances' : 'Hide balances';
    $('portfolio-hide').setAttribute('aria-pressed', String(hidden));
    const focusedToggle = document.activeElement?.dataset?.networkGroupToggle;
    const focusedBadge = document.activeElement?.closest('.network-health');
    const focusedChain = focusedBadge && $('portfolio-networks').contains(focusedBadge) ? focusedBadge.dataset.chain : undefined;
    $('portfolio-networks').replaceChildren(...groupedNetworkControls(Object.entries(networks), ([chain, c]) => {
      const rows = snap.rows.filter(r => r.chain === chain), ready = rows.every(r => r.balance !== null && r.keptAt === undefined);
      const lastRead = rows.filter(r => r.keptAt !== undefined).map(r => r.keptAt);
      const status = c.balanceUnavailable ? (lastRead.length ? `${unavailableBalanceLabel(chain)} · last read ${readTime(Math.min(...lastRead))}` : unavailableBalanceLabel(chain)) : rows.some(r => r.state === 'loading') || jobs.has(chain) ? 'Reading' : ready ? 'Balances read'
        : lastRead.length ? `Last read ${readTime(Math.min(...lastRead))}` : rows.every(r => r.state === 'idle') ? 'Not read' : 'Incomplete';
      // Historical lights show stale or failed reads; titles retain the full status.
      const reading = status === 'Reading';
      const health = !c.balanceUnavailable && rows.some(r => r.state === 'error') ? 'failed' : ready && rows.length && !c.balanceUnavailable ? 'current' : lastRead.length ? 'old' : 'none';
      // Use the existing selection path without navigating away from the current page.
      const badge = el('button', 'network-health'); badge.type = 'button'; badge.dataset.chain = chain;
      badge.dataset.health = health; badge.dataset.reading = String(reading);
      badge.title = `${c.name} · ${status}`; badge.setAttribute('aria-label', `${badge.title}. Use ${c.name} for Send / Receive`);
      badge.setAttribute('aria-pressed', String(chain === selected));
      badge.onclick = () => selectAsset(chain, c.symbol, 'choose');
      badge.append(networkIcon(c), el('span', '', c.name), el('span', 'health-light')); return badge;
    }, expandedNetworkGroups));
    if (focusedToggle) $('portfolio-networks').querySelector(`[data-network-group-toggle="${focusedToggle}"]`)?.focus({ preventScroll: true });
    if (focusedChain !== undefined) [...$('portfolio-networks').querySelectorAll('.network-health')].find(badge => badge.dataset.chain === focusedChain)?.focus({ preventScroll: true });
    for (const detail of $('balances').querySelectorAll('details.asset-group')) {
      if (detail.open) expandedAssets.add(detail.dataset.symbol); else expandedAssets.delete(detail.dataset.symbol);
    }
    const focused = document.activeElement, focusedGroup = focused?.closest('.asset-group')?.dataset.symbol;
    const focusedAction = focused?.getAttribute('aria-label'), focusedRowAction = focused?.dataset?.rowAction;
    renderReceiveActions();
    const groups = groupNetworks(snap.rows.map(row => jobs.has(row.chain) ? { ...row, state: 'loading' } : row), { hideZero });
    $('balances').replaceChildren(...groups.map(group => {
      const network = networks[group.chain];
      const detail = el('details', 'asset-group network-assets'); detail.dataset.symbol = group.chain; detail.dataset.chain = group.chain;
      detail.open = expandedAssets.has(group.chain);
      const summary = el('summary', 'asset-summary');
      const heading = el('button', 'network-heading-select', network.name); heading.type = 'button'; heading.setAttribute('aria-label', `Select ${network.name} network`);
      heading.onclick = event => { event.preventDefault(); event.stopPropagation(); selectAsset(group.chain, network.symbol, 'choose'); };
      summary.append(networkIcon(network), heading, el('span', 'asset-chevron', '⌄')); detail.append(summary);
      for (const row of group.rows) {
        const entry = el('div', `chain-holding${row.chain === selected ? ' selected' : ''}`); entry.dataset.chain = row.chain;
        const identity = el('button', 'holding-network holding-select'); identity.type = 'button';
        identity.setAttribute('aria-label', `Select ${row.symbol} on ${network.name}`);
        identity.append(icon(row.symbol, network), el('span', '', row.symbol)); identity.onclick = () => selectAsset(row.chain, row.symbol, 'choose');
        const value = el('span', 'holding-value');
        const state = row.state === 'loading' ? 'Reading…' : row.state === 'unsupported' ? unavailableBalanceLabel(row.chain) : row.state === 'idle' ? 'Not read' : (row.error || 'Balance unavailable');
        const amount = el('strong', '', text(row.balance === null ? state : `${displayAmount(row.balance)} ${row.symbol}`));
        if (row.balance !== null && !hidden) amount.title = `${row.balance} ${row.symbol}`;
        value.append(amount, el('small', '', row.keptAt !== undefined ? `Last read ${readTime(row.keptAt)}` : text(row.priceMissing ? 'Price unavailable' : usdText(row.usd, row.positive))));
        if (row.state === 'unsupported' && row.keptAt !== undefined) value.append(el('small', 'balance-note', unavailableBalanceLabel(row.chain)));
        if (row.state === 'error' && row.keptAt !== undefined) value.append(el('small', 'balance-error', `${row.error || 'Balance unavailable'}; showing last read.`));
        if (network.balanceNote) value.append(el('small', 'balance-note', network.balanceNote));
        entry.append(identity, value); detail.append(entry);
      }
      return detail;
    }));
    if (!groups.length) $('balances').append(el('p', 'hint balances-empty', 'No networks have a displayable nonzero balance. Uncheck Hide zero balances to show all networks.'));
    // Reading another network or expiring a quote must not interrupt keyboard navigation.
    if (focusedRowAction) $('balances').querySelector(`button[data-row-action="${CSS.escape(focusedRowAction)}"]`)?.focus({ preventScroll: true });
    if (focusedGroup) {
      const group = [...$('balances').children].find(node => node.dataset.symbol === focusedGroup);
      const control = focused?.matches('summary') ? group?.querySelector('summary')
        : [...(group?.querySelectorAll('button') || [])].find(button => button.getAttribute('aria-label') === focusedAction);
      control?.focus({ preventScroll: true });
    }
  }
  // `background`: an automatic read (setAutoRefresh, freshen) — the shown
  // values stay until the answer replaces them, and a failed read keeps them
  // (they go out of date by their own age, portfolioSnapshot).
  async function readChainBalances(chain, current, { background = false } = {}) {
    // No address yet (Cellframe/Ixios derivation still pending): stay "Reading…"
    // rather than issuing a request or reporting a false error.
    if (!addresses[chain]) { if (background) return false; for (const asset of assets.filter(a => a.chain === chain)) balances[asset.key] = { state: 'loading' }; render(); return false; }
    const controller = new AbortController(); jobs.set(chain, controller);
    if (background) backgroundJobs.add(controller);
    if (!background) for (const asset of assets.filter(a => a.chain === chain)) if (balances[asset.key]?.state !== 'ready') balances[asset.key] = { state: 'loading' };
    render();
    try {
      const rows = await readBalances(chain, addresses[chain], endpoints[chain], { signal: controller.signal });
      if (session === current && !controller.signal.aborted) {
        const result = chainBalances(chain, rows, Date.now(), assets);
        Object.assign(balances, result);
        keepRead(chain, result);
        return true;
      }
    } catch (error) {
      if (session === current && !controller.signal.aborted) for (const asset of assets.filter(a => a.chain === chain)) balances[asset.key] = { state: 'error', error: balanceErrorDetail(error) };
    } finally { backgroundJobs.delete(controller); if (session === current) { if (jobs.get(chain) === controller) jobs.delete(chain); render(); } }
    return false;
  }
  // Automatic reads in flight (0.1.96, W-08): a Refresh pressed meanwhile
  // cancels them and reads at once instead of being refused without a word.
  const backgroundJobs = new Set();
  function yieldToRefresh() {
    const running = [...jobs.values(), ...(priceJob ? [priceJob] : [])];
    if (!running.length) return true;
    if (!running.every(c => backgroundJobs.has(c))) return false;
    for (const c of running) c.abort();
    jobs.clear(); priceJob = undefined; backgroundJobs.clear();
    return true;
  }
  // The market prices, read again (an automatic read keeps the old quotes
  // when it fails).
  // A successful read replaces every quote: one the source no longer vouches
  // for is dropped (0.1.96, W-08); a failed automatic read keeps the old ones,
  // which still expire by their own age (PRICE_MAX_AGE).
  function readQuotes(current, controller) {
    return readPrices({ signal: controller.signal })
      .then(value => { if (session === current && !controller.signal.aborted) { quotes = value; pricesAt = Date.now(); return true; } return false; })
      .catch(() => false);
  }
  function updatedText() {
    const auto = autoMinutes ? ` Read again every ${autoMinutes} minutes while this page is shown.` : ' After 5 minutes a balance is shown as last read and leaves the total; prices expire after 15 minutes.';
    return `Last refresh: ${new Date(doneAt).toLocaleTimeString()}.${auto}`;
  }
  async function refresh({ background = false } = {}) {
    if (!addresses) return;
    if (background ? (jobs.size || priceJob) : !yieldToRefresh()) return;
    const current = session;
    readAt = Date.now();
    // Refresh keeps what is shown until each answer replaces it (0.1.102,
    // operator: "refresh ettiği anda hepsi boş oluyor … ikonlar gidiyor"): only
    // a row with no balance yet shows "Reading…"; the network badges say
    // "Reading" while their read runs; prices stay until new ones arrive.
    if (!background) for (const asset of assets) if (balances[asset.key]?.state !== 'ready') balances[asset.key] = { state: 'loading' };
    const controller = new AbortController(); priceJob = controller;
    if (background) backgroundJobs.add(controller);
    if (!background) $('portfolio-updated').textContent = 'Reading balances and market prices…';
    render();
    const priceRead = readQuotes(current, controller);
    const reads = chains.map(chain => readChainBalances(chain, current, { background }));
    const results = await Promise.allSettled([priceRead, ...reads]);
    backgroundJobs.delete(controller);
    if (session !== current || priceJob !== controller) return;      // cancelled by a Refresh, or the wallet closed
    priceJob = undefined;
    // "Last refresh" names the last read that brought something (0.1.96, W-08).
    if (results.some(r => r.status === 'fulfilled' && r.value === true)) doneAt = Date.now();
    $('portfolio-updated').textContent = doneAt ? updatedText() : 'Balances and prices could not be read just now.';
    render();
  }
  // One network chosen (src/app.js, the Send / Receive network): its balance,
  // and the prices, read again in the background when older than a minute.
  const FRESHEN_MS = 60000;
  function freshen(chain) {
    if (!addresses || !chains.includes(chain) || !addresses[chain] || jobs.has(chain) || priceJob) return;
    const current = session, now = Date.now();
    const read = assets.filter(a => a.chain === chain).map(a => balances[a.key]).filter(b => b?.state === 'ready').map(b => b.observedAt);
    if (read.length && now - Math.min(...read) < FRESHEN_MS) return;
    void readChainBalances(chain, current, { background: true });
    if (now - pricesAt >= FRESHEN_MS) {
      const controller = new AbortController(); priceJob = controller; backgroundJobs.add(controller);
      void readQuotes(current, controller).finally(() => { backgroundJobs.delete(controller); if (session === current && priceJob === controller) { priceJob = undefined; render(); } });
    }
  }
  // One network read again now, in the background, whatever the age of its
  // last read (0.1.102, operator: "nodus gönderdikten sonra hemen bakiye
  // güncellenmiyor"): a transaction of this wallet on it was just confirmed
  // (src/app.js checkRow). A read already running started before the
  // confirmation, so it is cancelled and replaced.
  function reread(chain) {
    if (!addresses || !chains.includes(chain) || !addresses[chain]) return;
    const running = jobs.get(chain);
    if (running) { running.abort(); jobs.delete(chain); backgroundJobs.delete(running); }
    void readChainBalances(chain, session, { background: true });
  }
  // Automatic updates: every `minutes` while the page is shown (0 = off).
  // A hidden page reads nothing; shown again after the interval, it reads at once.
  function autoTick() {
    if (!autoMinutes || !addresses || document.hidden) return;
    if (Date.now() - readAt < autoMinutes * 60000 - 1000) return;
    void refresh({ background: true });
  }
  function resetAssetView() {
    expandedAssets.clear();
    for (const detail of $('balances').querySelectorAll('details[open]')) detail.open = false;
  }
  function setHideZero(value) { hideZero = value === true; render(); }
  function setAutoRefresh(minutes) {
    autoMinutes = Number.isSafeInteger(minutes) && minutes > 0 ? minutes : 0;
    clearInterval(autoTimer); autoTimer = undefined;
    if (autoMinutes) autoTimer = setInterval(autoTick, 30000);
    // The Refresh buttons only when balances are not read automatically
    // (0.1.108, operator: "refresh networks var. Ona da gerek yok. Otomatik
    // refresh ediyoruz zaten"); with automatic updates Off they are the only
    // way to read again, so they come back.
    for (const id of ['portfolio-refresh', 'refresh']) $(id).hidden = autoMinutes > 0;
    if (doneAt && addresses && !jobs.size && !priceJob) $('portfolio-updated').textContent = updatedText();
    render();
  }
  // After the page's own handlers (0.1.96, W-08): a page shown again past its
  // idle deadline is locked first (src/app.js), and then nothing is read.
  document.addEventListener('visibilitychange', () => setTimeout(autoTick, 0));
  function clear() {
    session++; for (const job of jobs.values()) job.abort(); jobs.clear(); priceJob?.abort(); priceJob = undefined;
    clearInterval(timer); addresses = undefined; endpoints = undefined; balances = {}; quotes = {}; filter = 'all'; hidden = false; rowActions = {}; earn = {}; kept = {};
    readAt = 0; pricesAt = 0; doneAt = 0; backgroundJobs.clear(); expandedNetworkGroups.clear();
    $('portfolio-updated').textContent = ''; render();
  }
  // `kept`: entries saved with this wallet (src/activity-storage.js
  // parseBalances), shown until a fresh read replaces them.
  function open(publicAddresses, publicEndpoints, { automatic = true, kept: initial = {} } = {}) {
    clear(); addresses = { ...publicAddresses }; endpoints = { ...publicEndpoints };
    for (const [key, k] of Object.entries(initial)) kept[key] = { units: k.units, observedAt: k.observedAt, address: k.address };
    timer = setInterval(render, 30000); render(); if (automatic) void refresh();
  }
  function changeEndpoint(chain, endpoint) {
    if (!endpoints) return;
    // Cancel the old endpoint's reads so they cannot overwrite the new state.
    const savedAddresses = addresses, savedEndpoints = { ...endpoints, [chain]: endpoint }, savedActions = rowActions, savedKept = kept, savedGroups = [...expandedNetworkGroups];
    open(savedAddresses, savedEndpoints, { automatic: false, kept: savedKept });
    for (const group of savedGroups) expandedNetworkGroups.add(group);
    readAt = Date.now();                 // no automatic read right after: the line below asks for Refresh (0.1.96)
    rowActions = savedActions; render();
    $('portfolio-status').textContent = 'Network endpoint changed. Refresh all to read balances again.';
  }
  // Reports a late-arriving address (Cellframe, Ixios), or its failure (falsy
  // address), once local derivation settles. Ignored for a network with no
  // balance source (Nodus), which is never read. A session guard is unnecessary here
  // beyond the `addresses` check: open()/clear() always run before a stale
  // wallet's caller could reach this, and readChainBalances re-checks `session`
  // itself.
  function setAddress(chain, address) {
    if (!addresses || !Object.hasOwn(networks, chain)) return;
    // A network with no balance source yet (NODUS before its connection is
    // ready): the address is only remembered, so the balance last read for it
    // (kept, a saved wallet's too) is shown as last read; nothing is read (0.1.96).
    if (!chains.includes(chain)) { if (address) { addresses[chain] = address; render(); } return; }
    // The same address again (a kept one, then the derived one, 0.1.97) while
    // its read runs: that read answers for both.
    if (address && addresses[chain] === address && jobs.has(chain)) return;
    addresses[chain] = address;
    if (!address) { for (const asset of assets.filter(a => a.chain === chain)) balances[asset.key] = { state: 'error' }; render(); return; }
    void readChainBalances(chain, session);
  }
  // Replaces one listed network's definition (same chain key, same asset) —
  // today only NODUS, between receive-only and send-module-ready
  // (src/app.js setNodusReady). A network that stops having a balance source
  // has its read cancelled and its rows dropped; one that gains a source is
  // read as soon as setAddress() reports its address.
  // `keepRead` (pin availability changes, src/app.js syncNodusPins): when the
  // network's asset keys are unchanged, an in-flight read and the balances
  // already held stay — only the definition (token availability, so the
  // rows' actions, holdingActions) is replaced. It never aborts the very read
  // whose completion triggered the update.
  function setNetwork(chain, network, { keepRead = false, forgetKept = false } = {}) {
    if (!Object.hasOwn(networks, chain) || networks[chain] === network) return;
    const before = assets.filter(a => a.chain === chain);       // incl. the old network's tokens
    networks[chain] = network; flag();
    // Environment changes can share an address; address-only retained values
    // must be removed along with the active read.
    if (forgetKept) for (const key of Object.keys(kept)) if (key.startsWith(`${chain}:`)) delete kept[key];
    if (keepRead && network.balanceUnavailable !== true) {
      const after = assets.filter(a => a.chain === chain);
      if (sameAssetKeys(before, after)) { render(); return; }
    }
    jobs.get(chain)?.abort(); jobs.delete(chain);
    for (const asset of [...before, ...assets.filter(a => a.chain === chain)]) delete balances[asset.key];
    // The address stays (0.1.96): its last read balance (kept) is shown as
    // "last read" while the network has no source, e.g. NODUS reconnecting.
    render();
  }
  // Marks the selected network's rows in place (no re-render, so no focus change);
  // render() applies the same marks to rows it builds later.
  function setSelected(chain) {
    selected = chain;
    renderReceiveActions();
    freshen(chain);                      // read it again if older than a minute (0.1.93)
    for (const badge of $('portfolio-networks').querySelectorAll('.network-health')) badge.setAttribute('aria-pressed', String(badge.dataset.chain === chain));
    for (const entry of $('balances').querySelectorAll('.chain-holding')) {
      const current = entry.dataset.chain === chain, control = entry.querySelector('.holding-select');
      entry.classList.toggle('selected', current);
      if (current) control?.setAttribute('aria-current', 'true'); else control?.removeAttribute('aria-current');
    }
  }
  // Shows (`{ label, note, run }`) or removes (undefined) the extra action
  // `id` ('main' by default; NODUS also has 'faucet': "Get testnet coins")
  // under `chain`'s own asset group. Only an open portfolio shows one.
  function setAction(chain, action, id = 'main') {
    if (!Object.hasOwn(networks, chain) || typeof id !== 'string' || !/^[a-z]{1,12}$/.test(id)) return;
    if (action && addresses && typeof action.label === 'string' && typeof action.note === 'string' && typeof action.run === 'function') rowActions[chain] = { ...rowActions[chain], [id]: action };
    else if (!rowActions[chain]?.[id]) return;
    else { const { [id]: _gone, ...rest } = rowActions[chain]; if (Object.keys(rest).length) rowActions[chain] = rest; else delete rowActions[chain]; }
    render();
  }
  // Adds (true) or removes (false) the "Earn" button on `chain`'s rows.
  function setEarn(chain, available) {
    if (!Object.hasOwn(networks, chain) || !!earn[chain] === !!available) return;
    if (available) earn[chain] = true; else delete earn[chain];
    render();
  }
  $('portfolio-refresh').onclick = refresh;
  $('refresh').onclick = refresh;
  $('portfolio-hide').onclick = () => { hidden = !hidden; render(); };
  const filterButton = ([chain, network]) => {
    const button = el('button', 'network-filter', network.name); button.type = 'button'; button.dataset.chain = chain;
    button.onclick = () => { filter = chain; render(); }; return button;
  };
  // Portfolio always shows every network, independently of the transfer network.
  $('portfolio-filters').replaceChildren();
  $('portfolio-filters').hidden = true;
  render();
  return { open, clear, refresh, reread, changeEndpoint, setAddress, setSelected, setNetwork, setAction, setEarn, setAutoRefresh, setHideZero, resetAssetView };
}
