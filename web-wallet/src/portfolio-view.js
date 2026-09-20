import { CHAINS } from './config.js';
import { ASSETS, chainBalances, readPrices, portfolioSnapshot, groupAssets, usdText } from './portfolio.js';

const names = { ETH: 'Ethereum', BNB: 'BNB', SOL: 'Solana', TRX: 'TRON', USDT: 'Tether', USDC: 'USD Coin', DAI: 'Dai', USDD: 'USDD' };
const icons = new Set(['ETH', 'BNB', 'SOL', 'TRX', 'USDT']);
const $ = id => document.getElementById(id);
function el(tag, className, text) { const node = document.createElement(tag); node.className = className; if (text !== undefined) node.textContent = text; return node; }
function icon(symbol) {
  if (!icons.has(symbol)) return el('span', 'coin-icon coin-letter', symbol === 'USDC' ? '$' : symbol[0]);
  const img = el('img', 'coin-icon'); img.src = `/assets/coins/${symbol.toLowerCase()}.svg`; img.alt = ''; img.width = 36; img.height = 36; return img;
}

// This controller receives only public addresses, never a wallet or signing key.
export function createPortfolio({ readBalances, selectAsset }) {
  let addresses, endpoints, balances = {}, quotes = {}, filter = 'all', hidden = false, session = 0, timer, priceJob;
  const jobs = new Map();
  const text = value => hidden ? '••••' : value;
  function render() {
    const snap = portfolioSnapshot(balances, quotes);
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
    $('portfolio-networks').replaceChildren(...Object.entries(CHAINS).map(([chain, c]) => {
      const rows = snap.rows.filter(r => r.chain === chain), ready = rows.every(r => r.balance !== null);
      const status = rows.some(r => r.state === 'loading') ? 'Reading' : ready ? 'Balances read' : rows.every(r => r.state === 'idle') ? 'Not read' : 'Incomplete';
      const badge = el('span', 'network-health'); badge.append(icon(c.symbol), el('span', '', `${c.name} · ${status}`)); return badge;
    }));
    for (const button of $('portfolio-filters').querySelectorAll('button')) button.setAttribute('aria-pressed', String(button.dataset.chain === filter));
    const opened = new Set([...$('balances').querySelectorAll('details[open]')].map(d => d.dataset.symbol));
    const focused = document.activeElement, focusedGroup = focused?.closest('.asset-group')?.dataset.symbol;
    const focusedAction = focused?.getAttribute('aria-label');
    $('balances').replaceChildren(...groupAssets(snap.rows, filter).map(group => {
      const detail = el('details', 'asset-group'); detail.dataset.symbol = group.symbol; detail.open = opened.has(group.symbol);
      const summary = el('summary', 'asset-summary'), name = el('span', 'asset-name');
      name.append(el('strong', '', group.symbol), el('small', '', `${names[group.symbol]} · ${group.rows.length === 1 ? CHAINS[group.rows[0].chain].name : `${group.rows.length} networks`}`));
      const value = el('span', 'asset-value');
      value.append(el('strong', '', text(group.balance === null ? '—' : `${group.balance}${group.partialBalance ? ' known' : ''}`)),
        el('small', '', text(`${usdText(group.usd, group.positive)}${group.partialValue && group.usd !== null ? ' known' : ''}`)));
      summary.append(icon(group.symbol), name, value, el('span', 'asset-chevron', '⌄')); detail.append(summary);
      for (const row of group.rows) {
        const entry = el('div', 'chain-holding'), identity = el('span', 'holding-network');
        identity.append(icon(CHAINS[row.chain].symbol), el('span', '', CHAINS[row.chain].name));
        const value = el('span', 'holding-value');
        const state = row.state === 'loading' ? 'Reading…' : row.state === 'stale' ? 'Balance out of date' : row.state === 'idle' ? 'Not read' : 'Balance unavailable';
        value.append(el('strong', '', text(row.balance === null ? state : `${row.balance} ${row.symbol}`)),
          el('small', '', text(row.priceMissing ? 'Price unavailable' : usdText(row.usd, row.positive))));
        const actions = el('span', 'holding-actions');
        for (const action of ['Send', 'Receive']) {
          const button = el('button', 'secondary small', action); button.type = 'button';
          button.setAttribute('aria-label', `${action} ${row.symbol} on ${CHAINS[row.chain].name}`);
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
  async function refresh() {
    if (!addresses || jobs.size || priceJob) return;
    const current = session;
    quotes = {};
    for (const asset of ASSETS) balances[asset.key] = { state: 'loading' };
    const controller = new AbortController(); priceJob = controller;
    for (const chain of Object.keys(CHAINS)) jobs.set(chain, new AbortController());
    $('portfolio-updated').textContent = 'Reading balances and market prices…'; render();
    const priceRead = readPrices({ signal: controller.signal }).then(value => { if (session === current) quotes = value; }).catch(() => {});
    const reads = [...jobs].map(async ([chain, job]) => {
      try {
        const rows = await readBalances(chain, addresses[chain], endpoints[chain], { signal: job.signal });
        if (session === current) Object.assign(balances, chainBalances(chain, rows));
      } catch {
        if (session === current) for (const asset of ASSETS.filter(a => a.chain === chain)) balances[asset.key] = { state: 'error' };
      } finally { if (session === current) { jobs.delete(chain); render(); } }
    });
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
  $('portfolio-refresh').onclick = refresh;
  $('refresh').onclick = refresh;
  $('portfolio-hide').onclick = () => { hidden = !hidden; render(); };
  $('portfolio-filters').replaceChildren(...[['all', 'All networks'], ...Object.entries(CHAINS).map(([key, c]) => [key, c.name])].map(([chain, name]) => {
    const button = el('button', 'network-filter', name); button.type = 'button'; button.dataset.chain = chain;
    button.onclick = () => { filter = chain; render(); }; return button;
  }));
  render();
  return { open, clear, refresh, changeEndpoint };
}
