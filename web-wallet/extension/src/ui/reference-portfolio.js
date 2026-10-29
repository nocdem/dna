import { ASSETS, groupAssets, holdingActions, usdText, displayAmount } from '../../../src/portfolio.js';

// Rendering port of src/portfolio-view.js:4-44,118-229,446-452.
// Only public state and the document are injected; the asset markup is the
// web wallet's. Balance/price reads stay on the existing trusted port.
export function mountPortfolio(document, root, readSnapshot, selectAsset, refresh) {
  const $ = id => root.querySelector('#' + id);
  let filter = 'all', hidden = false, hideZero = true, selected = 'nodus', busy = false;
  const rowActions = {}, earn = {};
  const text = value => hidden ? '••••' : value;
  const readTime = ms => new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const names = { ETH: 'Ethereum', BNB: 'BNB', SOL: 'Solana', TRX: 'TRON', USDT: 'Tether', USDC: 'USD Coin', DAI: 'Dai', USDD: 'USDD', CPUNK: 'CPUNK' };
  // Asset symbol -> its own icon file. Keyed by symbol, not guessed from it, so an
  // asset can carry a different file extension/name than its lowercase symbol
  // (CPUNK's icon is a PNG, not a same-named SVG).
  const icons = { ETH: 'eth.svg', BNB: 'bnb.svg', SOL: 'sol.svg', TRX: 'trx.svg', USDT: 'usdt.svg', CPUNK: 'cpunk.png' };
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
    'bnb.svg': new URL('../../../src/assets/coins/bnb.svg', import.meta.url).href,
    'cellframe.svg': new URL('../../../src/assets/coins/cellframe.svg', import.meta.url).href,
    'cpunk.png': new URL('../../../src/assets/coins/cpunk.png', import.meta.url).href,
    'eth.svg': new URL('../../../src/assets/coins/eth.svg', import.meta.url).href,
    'nodus.svg': new URL('../../../src/assets/coins/nodus.svg', import.meta.url).href,
    'sol.svg': new URL('../../../src/assets/coins/sol.svg', import.meta.url).href,
    'trx.svg': new URL('../../../src/assets/coins/trx.svg', import.meta.url).href,
    'usdt.svg': new URL('../../../src/assets/coins/usdt.svg', import.meta.url).href,
    ...(import.meta.env.VITE_ENABLE_IXIOS === 'true' ? { 'ixios.png': new URL('../../../src/assets/coins/ixios.png', import.meta.url).href } : {})
  };
  function iconImg(file) { const img = el('img', 'coin-icon'); img.src = ICON_URLS[file]; img.dataset.icon = file; img.alt = ''; img.width = 36; img.height = 36; return img; }
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
  
  
  function render() {
    // Read again automatically: a balance counts until two minutes past its
    // next scheduled read, so a value is never crossed out between reads.
    const { snapshot: snap, networks, reading, readingChains, updatedAt } = readSnapshot();
    $('portfolio-total').textContent = text(usdText(snap.total, snap.positive));
    $('portfolio-label').textContent = snap.state === 'partial' ? 'Known value · incomplete' : snap.state === 'loading' ? 'Updating portfolio' : 'Estimated portfolio value';
    $('portfolio-status').textContent = snap.state === 'idle' ? 'Refresh all to read your balances and prices.'
      : snap.state === 'loading' ? `${snap.known} of ${ASSETS.length} asset values available. Reading all networks…`
      : snap.complete ? 'All supported asset balances are included.'
      : `${snap.missingBalances} balances and ${snap.missingPrices} prices unavailable or out of date. Missing values are excluded.`;
    $('portfolio-refresh').disabled = busy || reading;
    $('refresh').disabled = busy || reading;
    $('portfolio-updated').textContent = updatedAt
      ? `Last refresh: ${new Date(updatedAt).toLocaleTimeString()}. After 5 minutes a balance is shown as last read and leaves the total; prices expire after 15 minutes.`
      : reading ? 'Reading balances and market prices…' : '';
    $('portfolio-hide').textContent = hidden ? 'Show balances' : 'Hide balances';
    $('portfolio-hide').setAttribute('aria-pressed', String(hidden));
    $('portfolio-networks').replaceChildren(...Object.entries(networks).map(([chain, c]) => {
      const rows = snap.rows.filter(r => r.chain === chain), ready = rows.every(r => r.balance !== null && r.keptAt === undefined);
      const lastRead = rows.filter(r => r.keptAt !== undefined).map(r => r.keptAt);
      const status = c.balanceUnavailable ? (lastRead.length ? `Last read ${readTime(Math.min(...lastRead))}` : 'Balance not shown yet') : rows.some(r => r.state === 'loading') || readingChains.has(chain) ? 'Reading' : ready ? 'Balances read'
        : lastRead.length ? `Last read ${readTime(Math.min(...lastRead))}` : rows.every(r => r.state === 'idle') ? 'Not read' : 'Incomplete';
      // A light instead of the words (0.1.103, operator: "yeşil … stale
      // olanlar … sarı … bağlanamayanlar kırmızı"): green = every balance
      // read and current, amber = shown as last read (out of date, or no
      // source yet), red = the last read failed, grey = not read yet; it
      // pulses while a read runs. The words stay as the badge's title and
      // accessible name.
      const reading = status === 'Reading';
      const health = rows.some(r => r.state === 'error') ? 'failed' : ready && rows.length && !c.balanceUnavailable ? 'current' : lastRead.length ? 'old' : 'none';
      // A button (0.1.107, operator: "clickable yap … network
      // seçebilirsin"): it chooses this network — the TRANSFER NETWORK box
      // below names it and offers its actions — without scrolling or opening
      // anything (0.1.108, 'choose': "QR kodunu oraya gönderiyorsun … ben
      // oraya göndermeni istemiyorum"); the chosen network's badge is marked
      // (aria-pressed, setSelected).
      const badge = el('button', 'network-health'); badge.type = 'button'; badge.dataset.chain = chain;
      badge.dataset.health = health; badge.dataset.reading = String(reading);
      badge.title = `${c.name} · ${status}`; badge.setAttribute('aria-label', `${badge.title}. Use ${c.name} for Send / Receive`);
      badge.setAttribute('aria-pressed', String(chain === selected));
      badge.onclick = () => selectAsset(chain, c.symbol, 'choose');
      // The light at the right end, centred top to bottom (0.1.106, operator:
      // "tam ortalamak … sağa dayalı olması lazım").
      badge.append(networkIcon(c), el('span', '', c.name), el('span', 'health-light')); return badge;
    }));
    for (const button of $('portfolio-filters').querySelectorAll('button')) button.setAttribute('aria-pressed', String(button.dataset.chain === filter));
    const opened = new Set([...$('balances').querySelectorAll('details[open]')].map(d => d.dataset.symbol));
    const focused = document.activeElement, focusedGroup = focused?.closest('.asset-group')?.dataset.symbol;
    const focusedAction = focused?.getAttribute('aria-label'), focusedRowAction = focused?.dataset?.rowAction;
    const groups = groupAssets(snap.rows, filter, Object.fromEntries(Object.entries(networks).map(([key, c]) => [key, c.name])), { hideZero });
    // Every asset of this filter left out as a zero balance (0.1.113): say so,
    // never an empty box.
    if (!groups.length) { $('balances').replaceChildren(el('p', 'hint balances-empty', 'Nothing held here yet. Zero balances are hidden — Device & settings can show them.')); return; }
    $('balances').replaceChildren(...groups.flatMap(group => {
      const detail = el('details', 'asset-group'); detail.dataset.symbol = group.symbol; detail.open = opened.has(group.symbol);
      const summary = el('summary', 'asset-summary'), name = el('span', 'asset-name');
      const home = networks[group.rows[0].chain];
      name.append(el('strong', '', group.symbol), el('small', '', `${names[group.symbol] ?? group.symbol} · ${group.rows.length === 1 ? home.name : `${group.rows.length} networks`}`));
      const value = el('span', 'asset-value');
      const groupAmount = el('strong', '', text(group.balance === null ? '—' : `${displayAmount(group.balance)}${group.partialBalance ? ' known' : ''}`));
      if (group.balance !== null && !hidden) groupAmount.title = `${group.balance} ${group.symbol}`;
      value.append(groupAmount,
        el('small', '', group.rows.every(r => r.keptAt !== undefined) ? 'Last read' : text(`${usdText(group.usd, group.positive)}${group.partialValue && group.usd !== null ? ' known' : ''}`)));
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
        const state = row.unavailable === true ? 'Unavailable right now' : row.state === 'unsupported' ? 'Balance not shown yet' : row.state === 'loading' ? 'Reading…' : row.state === 'stale' ? 'Balance out of date' : row.state === 'idle' ? 'Not read' : 'Balance unavailable';
        const rowAmount = el('strong', '', text(row.balance === null ? state : `${displayAmount(row.balance)} ${row.symbol}`));
        if (row.balance !== null && !hidden) rowAmount.title = `${row.balance} ${row.symbol}`;
        value.append(rowAmount,
          el('small', '', row.keptAt !== undefined ? `${row.state === 'error' ? 'Read failed · last read' : 'Last read'} ${readTime(row.keptAt)}` : text(row.priceMissing ? 'Price unavailable' : usdText(row.usd, row.positive))));
        const actions = el('span', 'holding-actions');
        // an unavailable token is never offered for Send (holdingActions)
        for (const action of holdingActions(networks[row.chain], row, !!earn[row.chain])) {
          const button = el('button', 'secondary small', action); button.type = 'button';
          button.setAttribute('aria-label', `${action} ${row.symbol} on ${networks[row.chain].name}`);
          button.onclick = () => selectAsset(row.chain, row.symbol, action.toLowerCase()); actions.append(button);
        }
        entry.append(identity, value, actions); detail.append(entry);
      }
      // The network's extra action sits right under its asset group, outside
      // the collapsible rows so it is visible without expanding them.
      // Under the network's OWN asset only (a leading network's tokens, e.g.
      // tUSDT on NODUS, are groups of their own and carry no action), and
      // one block per action of that network (setAction `id`).
      const chains = [...new Set(group.rows.filter(row => row.symbol === networks[row.chain].symbol).map(row => row.chain))].filter(chain => rowActions[chain]);
      return [detail, ...chains.flatMap(chain => Object.entries(rowActions[chain]).map(([id, action]) => {
        const block = el('div', 'asset-action notice');
        const button = el('button', 'small', action.label); button.type = 'button'; button.dataset.rowAction = id === 'main' ? chain : `${chain}:${id}`;
        // The button is handed to the action so it can show its own
        // "Preparing…" state (src/app.js showPreparing).
        button.onclick = () => action.run(button);
        block.append(el('p', '', action.note), button);
        return block;
      }))];
    }));
    // Reading another network or expiring a quote must not interrupt keyboard navigation.
    if (focusedRowAction) $('balances').querySelector(`button[data-row-action="${CSS.escape(focusedRowAction)}"]`)?.focus({ preventScroll: true });
    if (focusedGroup) {
      const group = [...$('balances').children].find(node => node.dataset.symbol === focusedGroup);
      const control = focused?.matches('summary') ? group?.querySelector('summary')
        : [...(group?.querySelectorAll('button') || [])].find(button => button.getAttribute('aria-label') === focusedAction);
      control?.focus({ preventScroll: true });
    }
  }

  function filters() {
    const { networks } = readSnapshot();
    $('portfolio-filters').replaceChildren(...[['all', 'All networks'], ...Object.entries(networks).map(([key, c]) => [key, c.name])].map(([chain, name]) => {
      const button = el('button', 'network-filter', name); button.type = 'button'; button.dataset.chain = chain;
      button.onclick = () => { filter = chain; render(); }; return button;
    }));
  }
  $('portfolio-refresh').onclick = refresh;
  $('refresh').onclick = refresh;
  $('portfolio-hide').onclick = () => { hidden = !hidden; render(); };
  filters(); render();
  return {
    update: render,
    setBusy(value) { busy = value; render(); },
    setSelected(chain) { selected = chain; render(); },
    setHideZero(value) { hideZero = value; render(); },
  };
}
