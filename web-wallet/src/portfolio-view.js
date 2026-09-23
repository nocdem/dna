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
// notActive?, ... }, asset }` entries (Cellframe/CPUNK_ASSET, and Ixios when its
// build flag is on): unpriced, receive-only networks merged after the permanent
// CHAINS/ASSETS registry. Their addresses are derived later than the others
// (asynchronous local derivation, not part of deriveWallet()), so their balance
// reads are not started at open() alongside the rest; a read starts once
// setAddress() reports the derived address, or the row is marked errored if
// derivation fails. A `notActive` network's balance is never read at all — no
// request, no stored balance state — and its rows and badge say "Not active yet".
export function createPortfolio({ readBalances, selectAsset, extraNetworks = [] }) {
  const networks = { ...CHAINS, ...Object.fromEntries(extraNetworks.map(({ network, asset }) => [asset.chain, network])) };
  const assets = [...ASSETS, ...extraNetworks.map(({ asset }) => asset)];
  const chains = Object.keys(networks);
  const inactive = chain => !!networks[chain].notActive;
  const NOT_ACTIVE = 'Not active yet';
  let addresses, endpoints, balances = {}, quotes = {}, filter = 'all', hidden = false, session = 0, timer, priceJob;
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
      const status = inactive(chain) ? NOT_ACTIVE : rows.some(r => r.state === 'loading') ? 'Reading' : ready ? 'Balances read' : rows.every(r => r.state === 'idle') ? 'Not read' : 'Incomplete';
      const badge = el('span', 'network-health'); badge.append(networkIcon(c), el('span', '', `${c.name} · ${status}`)); return badge;
    }));
    for (const button of $('portfolio-filters').querySelectorAll('button')) button.setAttribute('aria-pressed', String(button.dataset.chain === filter));
    const opened = new Set([...$('balances').querySelectorAll('details[open]')].map(d => d.dataset.symbol));
    const focused = document.activeElement, focusedGroup = focused?.closest('.asset-group')?.dataset.symbol;
    const focusedAction = focused?.getAttribute('aria-label');
    $('balances').replaceChildren(...groupAssets(snap.rows, filter).map(group => {
      const detail = el('details', 'asset-group'); detail.dataset.symbol = group.symbol; detail.open = opened.has(group.symbol);
      const summary = el('summary', 'asset-summary'), name = el('span', 'asset-name');
      const home = networks[group.rows[0].chain], groupInactive = group.rows.every(row => inactive(row.chain));
      name.append(el('strong', '', group.symbol), el('small', '', `${names[group.symbol] ?? group.symbol} · ${group.rows.length === 1 ? home.name : `${group.rows.length} networks`}`));
      const value = el('span', 'asset-value');
      value.append(el('strong', '', text(group.balance === null ? '—' : `${group.balance}${group.partialBalance ? ' known' : ''}`)),
        el('small', '', text(groupInactive ? NOT_ACTIVE : `${usdText(group.usd, group.positive)}${group.partialValue && group.usd !== null ? ' known' : ''}`)));
      summary.append(icon(group.symbol, home), name, value, el('span', 'asset-chevron', '⌄')); detail.append(summary);
      for (const row of group.rows) {
        const entry = el('div', 'chain-holding'), identity = el('span', 'holding-network');
        identity.append(networkIcon(networks[row.chain]), el('span', '', networks[row.chain].name));
        const value = el('span', 'holding-value');
        const state = row.state === 'loading' ? 'Reading…' : row.state === 'stale' ? 'Balance out of date' : row.state === 'idle' ? 'Not read' : 'Balance unavailable';
        // A not-active network never has a balance: show no amount rather than
        // a state that suggests a read could produce one (or a false zero).
        if (inactive(row.chain)) value.append(el('strong', '', text('—')), el('small', '', text(NOT_ACTIVE)));
        else value.append(el('strong', '', text(row.balance === null ? state : `${row.balance} ${row.symbol}`)),
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
    // Never read a not-active network: no request, and no balance state stored.
    if (inactive(chain)) return;
    // No address yet (Cellframe derivation still pending): stay "Reading…"
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
    for (const asset of assets) if (!inactive(asset.chain)) balances[asset.key] = { state: 'loading' };
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
  // address), once local derivation settles. A session guard is unnecessary here
  // beyond the `addresses` check: open()/clear() always run before a stale
  // wallet's caller could reach this, and readChainBalances re-checks `session`
  // itself. A not-active network only records the address: it is never read.
  function setAddress(chain, address) {
    if (!addresses) return;
    addresses[chain] = address;
    if (inactive(chain)) return;
    if (!address) { for (const asset of assets.filter(a => a.chain === chain)) balances[asset.key] = { state: 'error' }; render(); return; }
    void readChainBalances(chain, session);
  }
  $('portfolio-refresh').onclick = refresh;
  $('refresh').onclick = refresh;
  $('portfolio-hide').onclick = () => { hidden = !hidden; render(); };
  $('portfolio-filters').replaceChildren(...[['all', 'All networks'], ...Object.entries(networks).map(([key, c]) => [key, c.name])].map(([chain, name]) => {
    const button = el('button', 'network-filter', name); button.type = 'button'; button.dataset.chain = chain;
    button.onclick = () => { filter = chain; render(); }; return button;
  }));
  render();
  return { open, clear, refresh, changeEndpoint, setAddress };
}
