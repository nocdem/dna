import { CHAINS } from './config.js';
import { ASSETS, chainBalances, readPrices, portfolioSnapshot, groupAssets, usdText } from './portfolio.js';

const names = { ETH: 'Ethereum', BNB: 'BNB', SOL: 'Solana', TRX: 'TRON', USDT: 'Tether', USDC: 'USD Coin', DAI: 'Dai', USDD: 'USDD', CPUNK: 'CPUNK' };
// Asset symbol -> its own icon file. Keyed by symbol, not guessed from it, so an
// asset can carry a different file extension/name than its lowercase symbol
// (CPUNK's icon is a PNG, not a same-named SVG).
const icons = { ETH: 'eth.svg', BNB: 'bnb.svg', SOL: 'sol.svg', TRX: 'trx.svg', USDT: 'usdt.svg', CPUNK: 'cpunk.png' };
const $ = id => document.getElementById(id);
function el(tag, className, text) { const node = document.createElement(tag); node.className = className; if (text !== undefined) node.textContent = text; return node; }
function iconImg(file) { const img = el('img', 'coin-icon'); img.src = `/assets/coins/${file}`; img.alt = ''; img.width = 36; img.height = 36; return img; }
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
export function createPortfolio({ readBalances, selectAsset, leadingNetworks = [], extraNetworks = [] }) {
  const entries = (list) => Object.fromEntries(list.map(({ network, asset }) => [asset.chain, network]));
  const networks = { ...entries(leadingNetworks), ...CHAINS, ...entries(extraNetworks) };
  const flagged = ({ network, asset }) => network.balanceUnavailable ? { ...asset, balanceUnavailable: true } : asset;
  const assets = [...leadingNetworks.map(flagged), ...ASSETS, ...extraNetworks.map(flagged)];
  const chains = Object.keys(networks).filter(chain => !networks[chain].balanceUnavailable);
  // `selected`: the network chosen in the Send / Receive panel, set by the app
  // through setSelected(). It is UI state, not wallet state, so clear() keeps it.
  let addresses, endpoints, balances = {}, quotes = {}, filter = 'all', hidden = false, session = 0, timer, priceJob, selected;
  const jobs = new Map();
  const text = value => hidden ? '••••' : value;
  function render() {
    const snap = portfolioSnapshot(balances, quotes, Date.now(), assets);
    $('portfolio-total').textContent = text(usdText(snap.total, snap.positive));
    $('portfolio-label').textContent = snap.state === 'partial' ? 'Known value · incomplete' : snap.state === 'loading' ? 'Updating portfolio' : 'Estimated portfolio value';
    $('portfolio-status').textContent = snap.state === 'idle' ? 'Refresh all to read your balances and prices.'
      : snap.state === 'loading' ? `${snap.known} of ${ASSETS.length} asset values available. Reading all networks…`
      : snap.complete ? 'All supported asset balances are included.'
      : `${snap.missingBalances} balances and ${snap.missingPrices} prices unavailable or out of date. Missing values are excluded.`;
    $('portfolio-refresh').disabled = jobs.size > 0 || !!priceJob;
    $('refresh').disabled = jobs.size > 0 || !!priceJob;
    $('portfolio-hide').textContent = hidden ? 'Show balances' : 'Hide balances';
    $('portfolio-hide').setAttribute('aria-pressed', String(hidden));
    $('portfolio-networks').replaceChildren(...Object.entries(networks).map(([chain, c]) => {
      const rows = snap.rows.filter(r => r.chain === chain), ready = rows.every(r => r.balance !== null);
      const status = c.balanceUnavailable ? 'Balance not shown yet' : rows.some(r => r.state === 'loading') ? 'Reading' : ready ? 'Balances read' : rows.every(r => r.state === 'idle') ? 'Not read' : 'Incomplete';
      const badge = el('span', 'network-health'); badge.append(networkIcon(c), el('span', '', `${c.name} · ${status}`)); return badge;
    }));
    for (const button of $('portfolio-filters').querySelectorAll('button')) button.setAttribute('aria-pressed', String(button.dataset.chain === filter));
    const opened = new Set([...$('balances').querySelectorAll('details[open]')].map(d => d.dataset.symbol));
    const focused = document.activeElement, focusedGroup = focused?.closest('.asset-group')?.dataset.symbol;
    const focusedAction = focused?.getAttribute('aria-label');
    $('balances').replaceChildren(...groupAssets(snap.rows, filter).map(group => {
      const detail = el('details', 'asset-group'); detail.dataset.symbol = group.symbol; detail.open = opened.has(group.symbol);
      const summary = el('summary', 'asset-summary'), name = el('span', 'asset-name');
      const home = networks[group.rows[0].chain];
      name.append(el('strong', '', group.symbol), el('small', '', `${names[group.symbol] ?? group.symbol} · ${group.rows.length === 1 ? home.name : `${group.rows.length} networks`}`));
      const value = el('span', 'asset-value');
      value.append(el('strong', '', text(group.balance === null ? '—' : `${group.balance}${group.partialBalance ? ' known' : ''}`)),
        el('small', '', text(`${usdText(group.usd, group.positive)}${group.partialValue && group.usd !== null ? ' known' : ''}`)));
      summary.append(icon(group.symbol, home), name, value, el('span', 'asset-chevron', '⌄')); detail.append(summary);
      for (const row of group.rows) {
        // The whole row selects its network for the Send / Receive panel (0.1.22);
        // the network name is the row's keyboard control. Its aria-label is unique
        // within the group, so the focus restore below finds it after a re-render.
        const entry = el('div', `chain-holding${row.chain === selected ? ' selected' : ''}`);
        entry.dataset.chain = row.chain;
        const identity = el('button', 'holding-network holding-select'); identity.type = 'button';
        identity.setAttribute('aria-label', `Select ${row.symbol} on ${networks[row.chain].name}`);
        if (row.chain === selected) identity.setAttribute('aria-current', 'true');
        identity.append(networkIcon(networks[row.chain]), el('span', '', networks[row.chain].name));
        identity.onclick = () => selectAsset(row.chain, row.symbol, 'select');
        entry.onclick = event => { if (!event.target.closest('button')) selectAsset(row.chain, row.symbol, 'select'); };
        const value = el('span', 'holding-value');
        const state = row.state === 'unsupported' ? 'Balance not shown yet' : row.state === 'loading' ? 'Reading…' : row.state === 'stale' ? 'Balance out of date' : row.state === 'idle' ? 'Not read' : 'Balance unavailable';
        value.append(el('strong', '', text(row.balance === null ? state : `${row.balance} ${row.symbol}`)),
          el('small', '', text(row.priceMissing ? 'Price unavailable' : usdText(row.usd, row.positive))));
        const actions = el('span', 'holding-actions');
        for (const action of networks[row.chain].receiveOnly ? ['Receive'] : ['Send', 'Receive']) {
          const button = el('button', 'secondary small', action); button.type = 'button';
          button.setAttribute('aria-label', `${action} ${row.symbol} on ${networks[row.chain].name}`);
          button.onclick = () => selectAsset(row.chain, row.symbol, action.toLowerCase()); actions.append(button);
        }
        entry.append(identity, value, actions); detail.append(entry);
      }
      return detail;
    }));
    // Reading another network or expiring a quote must not interrupt keyboard navigation.
    if (focusedGroup) {
      const group = [...$('balances').children].find(node => node.dataset.symbol === focusedGroup);
      const control = focused?.matches('summary') ? group?.querySelector('summary')
        : [...(group?.querySelectorAll('button') || [])].find(button => button.getAttribute('aria-label') === focusedAction);
      control?.focus({ preventScroll: true });
    }
  }
  async function readChainBalances(chain, current) {
    // No address yet (Cellframe/Ixios derivation still pending): stay "Reading…"
    // rather than issuing a request or reporting a false error.
    if (!addresses[chain]) { for (const asset of assets.filter(a => a.chain === chain)) balances[asset.key] = { state: 'loading' }; render(); return; }
    const controller = new AbortController(); jobs.set(chain, controller);
    for (const asset of assets.filter(a => a.chain === chain)) balances[asset.key] = { state: 'loading' };
    render();
    try {
      const rows = await readBalances(chain, addresses[chain], endpoints[chain], { signal: controller.signal });
      if (session === current) Object.assign(balances, chainBalances(chain, rows, Date.now(), assets));
    } catch {
      if (session === current) for (const asset of assets.filter(a => a.chain === chain)) balances[asset.key] = { state: 'error' };
    } finally { if (session === current) { jobs.delete(chain); render(); } }
  }
  async function refresh() {
    if (!addresses || jobs.size || priceJob) return;
    const current = session;
    quotes = {};
    for (const asset of assets) balances[asset.key] = { state: 'loading' };
    const controller = new AbortController(); priceJob = controller;
    $('portfolio-updated').textContent = 'Reading balances and market prices…'; render();
    const priceRead = readPrices({ signal: controller.signal }).then(value => { if (session === current) quotes = value; }).catch(() => {});
    const reads = chains.map(chain => readChainBalances(chain, current));
    await Promise.allSettled([priceRead, ...reads]);
    if (session !== current) return;
    priceJob = undefined;
    $('portfolio-updated').textContent = `Last refresh: ${new Date().toLocaleTimeString()}. Balances expire after 5 minutes; prices after 15 minutes.`;
    render();
  }
  function clear() {
    session++; for (const job of jobs.values()) job.abort(); jobs.clear(); priceJob?.abort(); priceJob = undefined;
    clearInterval(timer); addresses = undefined; endpoints = undefined; balances = {}; quotes = {}; filter = 'all'; hidden = false;
    $('portfolio-updated').textContent = ''; render();
  }
  function open(publicAddresses, publicEndpoints, { automatic = true } = {}) {
    clear(); addresses = { ...publicAddresses }; endpoints = { ...publicEndpoints };
    timer = setInterval(render, 30000); render(); if (automatic) void refresh();
  }
  function changeEndpoint(chain, endpoint) {
    if (!endpoints) return;
    // Cancel the old endpoint's reads so they cannot overwrite the new state.
    const savedAddresses = addresses, savedEndpoints = { ...endpoints, [chain]: endpoint };
    open(savedAddresses, savedEndpoints, { automatic: false });
    $('portfolio-status').textContent = 'Network endpoint changed. Refresh all to read balances again.';
  }
  // Reports a late-arriving address (Cellframe, Ixios), or its failure (falsy
  // address), once local derivation settles. Ignored for a network with no
  // balance source (Nodus), which is never read. A session guard is unnecessary here
  // beyond the `addresses` check: open()/clear() always run before a stale
  // wallet's caller could reach this, and readChainBalances re-checks `session`
  // itself.
  function setAddress(chain, address) {
    if (!addresses || !chains.includes(chain)) return;
    addresses[chain] = address;
    if (!address) { for (const asset of assets.filter(a => a.chain === chain)) balances[asset.key] = { state: 'error' }; render(); return; }
    void readChainBalances(chain, session);
  }
  // Marks the selected network's rows in place (no re-render, so no focus change);
  // render() applies the same marks to rows it builds later.
  function setSelected(chain) {
    selected = chain;
    for (const entry of $('balances').querySelectorAll('.chain-holding')) {
      const current = entry.dataset.chain === chain, control = entry.querySelector('.holding-select');
      entry.classList.toggle('selected', current);
      if (current) control?.setAttribute('aria-current', 'true'); else control?.removeAttribute('aria-current');
    }
  }
  $('portfolio-refresh').onclick = refresh;
  $('refresh').onclick = refresh;
  $('portfolio-hide').onclick = () => { hidden = !hidden; render(); };
  $('portfolio-filters').replaceChildren(...[['all', 'All networks'], ...Object.entries(networks).map(([key, c]) => [key, c.name])].map(([chain, name]) => {
    const button = el('button', 'network-filter', name); button.type = 'button'; button.dataset.chain = chain;
    button.onclick = () => { filter = chain; render(); }; return button;
  }));
  render();
  return { open, clear, refresh, changeEndpoint, setAddress, setSelected };
}
