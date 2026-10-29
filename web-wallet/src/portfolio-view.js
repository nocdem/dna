import { CHAINS } from './config.js';
import { ASSETS, chainBalances, holdingActions, sameAssetKeys, readPrices as defaultReadPrices, portfolioSnapshot, groupAssets, usdText, displayAmount } from './portfolio.js';

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
      : snap.state === 'loading' ? `${snap.known} of ${ASSETS.length} asset values available. Reading all networks…`
      : snap.complete ? 'All supported asset balances are included.'
      : `${snap.missingBalances} balances and ${snap.missingPrices} prices unavailable or out of date. Missing values are excluded.`;
    $('portfolio-refresh').disabled = jobs.size > 0 || !!priceJob;
    $('refresh').disabled = jobs.size > 0 || !!priceJob;
    $('portfolio-hide').textContent = hidden ? 'Show balances' : 'Hide balances';
    $('portfolio-hide').setAttribute('aria-pressed', String(hidden));
    $('portfolio-networks').replaceChildren(...Object.entries(networks).map(([chain, c]) => {
      const rows = snap.rows.filter(r => r.chain === chain), ready = rows.every(r => r.balance !== null && r.keptAt === undefined);
      const lastRead = rows.filter(r => r.keptAt !== undefined).map(r => r.keptAt);
      const status = c.balanceUnavailable ? (lastRead.length ? `Last read ${readTime(Math.min(...lastRead))}` : 'Balance not shown yet') : rows.some(r => r.state === 'loading') || jobs.has(chain) ? 'Reading' : ready ? 'Balances read'
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
    } catch {
      if (session === current && !controller.signal.aborted && !background) for (const asset of assets.filter(a => a.chain === chain)) balances[asset.key] = { state: 'error' };
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
    readAt = 0; pricesAt = 0; doneAt = 0; backgroundJobs.clear();
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
    const savedAddresses = addresses, savedEndpoints = { ...endpoints, [chain]: endpoint }, savedActions = rowActions, savedKept = kept;
    open(savedAddresses, savedEndpoints, { automatic: false, kept: savedKept });
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
  function setNetwork(chain, network, { keepRead = false } = {}) {
    if (!Object.hasOwn(networks, chain) || networks[chain] === network) return;
    const before = assets.filter(a => a.chain === chain);       // incl. the old network's tokens
    networks[chain] = network; flag();
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
  $('portfolio-filters').replaceChildren(...[['all', 'All networks'], ...Object.entries(networks).map(([key, c]) => [key, c.name])].map(([chain, name]) => {
    const button = el('button', 'network-filter', name); button.type = 'button'; button.dataset.chain = chain;
    button.onclick = () => { filter = chain; render(); }; return button;
  }));
  render();
  return { open, clear, refresh, reread, changeEndpoint, setAddress, setSelected, setNetwork, setAction, setEarn, setAutoRefresh, setHideZero };
}
