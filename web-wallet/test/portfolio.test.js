import test from 'node:test';
import assert from 'node:assert/strict';
import { ASSETS, CPUNK_ASSET, PRICE_URL, BALANCE_MAX_AGE, PRICE_MAX_AGE, balanceUnits, chainBalances, parsePrices, readPrices, portfolioSnapshot, groupAssets, usdText } from '../src/portfolio.js';
import { IXIOS_NETWORK, IXIOS_ASSET } from '../src/ixios/network.js';
import { NODUS_NETWORK, NODUS_ASSET } from '../src/nodus/network.js';
const now = 1789918200000;
const coins = () => Object.fromEntries(ASSETS.map(a => [a.priceId, { price: 2, symbol: a.symbol, decimals: a.decimals, timestamp: now / 1000, confidence: .99 }]));
const ready = () => Object.fromEntries(ASSETS.map(a => [a.key, { state: 'ready', units: 0n, observedAt: now }]));
test('portfolio values configured assets by chain/contract and keeps amounts exact', () => {
  assert.equal(ASSETS.length, 14); assert.ok(!ASSETS.some(a => ['NODUS', 'CPUNK'].includes(a.symbol)));
  const balances = ready();
  for (const [key, amount] of [['ethereum:USDT','1.000001'], ['bsc:USDT','2.000000000000000001'], ['solana:USDT','3']]) {
    const asset = ASSETS.find(a => a.key === key); balances[key].units = balanceUnits(amount, asset.decimals);
  }
  const snap = portfolioSnapshot(balances, parsePrices({ coins: coins() }, now), now);
  assert.equal(snap.complete, true); assert.equal(snap.total, 1200000200n);
  assert.equal(usdText(snap.total), '$12.00');
  const grouped = groupAssets(snap.rows).find(g => g.symbol === 'USDT');
  assert.equal(grouped.balance, '6.000001000000000001'); assert.equal(grouped.rows.length, 4);
  assert.equal(groupAssets(snap.rows,'bsc').find(g=>g.symbol==='USDT').balance,'2.000000000000000001');
});
test('missing or failed balances and prices cannot become a complete zero total', () => {
  assert.equal(portfolioSnapshot({}, {}, now).total, null);
  const balances = ready(); balances['ethereum:ETH'] = {state:'error'};
  let snap = portfolioSnapshot(balances, {}, now);
  assert.equal(snap.complete, false); assert.equal(snap.total, null); assert.equal(snap.missingBalances,1);
  balances['ethereum:ETH'] = {state:'ready',units:10n**18n,observedAt:now};
  snap = portfolioSnapshot(balances,{},now);
  assert.equal(snap.total,null); assert.equal(snap.missingPrices,1);
  balances['solana:SOL']={state:'error'};
  snap=portfolioSnapshot(balances,parsePrices({coins:coins()},now),now);
  assert.equal(snap.total,200000000n);assert.equal(snap.complete,false);
  assert.equal(portfolioSnapshot(ready(),{},now).total,0n); // Known zero holdings need no price assumption.
});
test('stale balances or quotes are explicitly excluded from current totals', () => {
  const balances=ready(),quotes=parsePrices({coins:coins()},now);
  balances['ethereum:ETH'].units=10n**18n;
  let snap=portfolioSnapshot(balances,quotes,now+BALANCE_MAX_AGE+1);
  assert.equal(snap.total,null);assert.ok(snap.rows.every(r=>r.state==='stale'));
  quotes['ethereum:ETH'].observedAt=now-PRICE_MAX_AGE-1;
  snap=portfolioSnapshot(balances,quotes,now);assert.equal(snap.total,null);assert.equal(snap.missingPrices,1);
});
test('reject invalid prices, future timestamps and mismatched contract metadata', () => {
  const asset=ASSETS.find(a=>a.key==='ethereum:USDT');
  for(const invalid of [{price:0},{price:-1},{price:Infinity},{price:NaN},{price:1e10},{price:'2'}, {timestamp:now/1000+61},{timestamp:(now-PRICE_MAX_AGE)/1000-1},{confidence:0.1},{confidence:NaN},{symbol:'WRONG'},{decimals:18}]) {
    const data=coins();data[asset.priceId]={...data[asset.priceId],...invalid};
    assert.equal(parsePrices({coins:data},now)[asset.key],undefined,JSON.stringify(invalid));
  }
  assert.throws(()=>parsePrices({},now));
});
test('balance rows cannot silently disappear, duplicate or exceed token precision', () => {
  const result=chainBalances('ethereum',[{symbol:'ETH',balance:'1.0'},{symbol:'USDT',balance:'1'},{symbol:'USDT',balance:'2'},{symbol:'USDC',balance:'0.0000001'}],now);
  assert.equal(result['ethereum:ETH'].units,10n**18n);
  for(const token of ['USDT','USDC','DAI'])assert.equal(result[`ethereum:${token}`].state,'error');
  for(const value of ['NaN','1e3','-1','0x1', '9'.repeat(80)])assert.throws(()=>balanceUnits(value,18));
  assert.equal(usdText(0n,true),'<$0.01'); assert.equal(usdText(1n),'<$0.01'); assert.equal(usdText(0n),'$0.00');
});
test('CPUNK is an unpriced, opt-in row: no priceId, no PRICE_URL entry, never counted in the USD total or completeness', () => {
  assert.equal(CPUNK_ASSET.priceId, undefined);
  assert.equal(CPUNK_ASSET.chain, 'cellframe'); assert.equal(CPUNK_ASSET.key, 'cellframe:CPUNK');
  assert.ok(!PRICE_URL.includes('cellframe')); assert.ok(!PRICE_URL.includes('CPUNK'));
  const withCpunk = [...ASSETS, CPUNK_ASSET];
  const result = chainBalances('cellframe', [{ symbol: 'CPUNK', balance: '5.5' }], now, withCpunk);
  assert.equal(result['cellframe:CPUNK'].units, balanceUnits('5.5', 18));
  // Priced assets all known and zero; CPUNK itself known and zero. The portfolio
  // is still reported complete (matches the 14-asset-only promise) and CPUNK
  // contributes nothing to the total even at a known, non-error balance.
  const balances = { ...ready(), 'cellframe:CPUNK': { state: 'ready', units: 0n, observedAt: now } };
  let snap = portfolioSnapshot(balances, parsePrices({ coins: coins() }, now), now, withCpunk);
  assert.equal(snap.complete, true); assert.equal(snap.total, 0n);
  const cpunkRow = snap.rows.find(r => r.key === 'cellframe:CPUNK');
  assert.equal(cpunkRow.usd, null); assert.equal(usdText(cpunkRow.usd), '—');
  // A CPUNK read failure does not block completeness of the priced portfolio,
  // and does not silently become a zero balance either.
  balances['cellframe:CPUNK'] = { state: 'error' };
  snap = portfolioSnapshot(balances, parsePrices({ coins: coins() }, now), now, withCpunk);
  assert.equal(snap.complete, true); assert.equal(snap.rows.find(r => r.key === 'cellframe:CPUNK').balance, null);
  // Grouping sorts CPUNK after the other configured symbols.
  const grouped = groupAssets(snap.rows);
  assert.equal(grouped.at(-1).symbol, 'CPUNK'); assert.equal(grouped.find(g => g.symbol === 'CPUNK').usd, null);
});
test('IXIOS is an unpriced, receive-only row like CPUNK: no priceId, no PRICE_URL entry, never counted in the USD total or completeness, sorts last', () => {
  assert.equal(IXIOS_ASSET.priceId, undefined);
  assert.equal(IXIOS_ASSET.chain, 'ixios'); assert.equal(IXIOS_ASSET.key, 'ixios:IXIOS'); assert.equal(IXIOS_ASSET.decimals, 18);
  assert.equal(IXIOS_NETWORK.symbol, IXIOS_ASSET.symbol); assert.equal(IXIOS_NETWORK.icon, 'ixios.png');
  assert.equal(IXIOS_NETWORK.receiveOnly, true); assert.equal(Object.hasOwn(IXIOS_NETWORK, 'notActive'), false);
  assert.equal(IXIOS_NETWORK.endpoint, 'https://ixios-rpc.innova.limited');
  assert.deepEqual(IXIOS_NETWORK.rpcOptions, [{ url: IXIOS_NETWORK.endpoint, label: 'Ixios public RPC' }]); assert.deepEqual(IXIOS_NETWORK.tokens, []);
  assert.equal(IXIOS_NETWORK.sendNote, 'Sending IXIOS is not available in this release. The Ixios network does not accept this address type yet.');
  assert.ok(!/ixios/i.test(PRICE_URL));
  const withBoth = [...ASSETS, CPUNK_ASSET, IXIOS_ASSET];
  const result = chainBalances('ixios', [{ symbol: 'IXIOS', balance: '7.25' }], now, withBoth);
  assert.equal(result['ixios:IXIOS'].units, balanceUnits('7.25', 18));
  // Priced assets all known and zero; IXIOS known and non-zero. The portfolio is
  // still complete, and IXIOS contributes nothing to the total.
  const balances = { ...ready(), 'cellframe:CPUNK': { state: 'ready', units: 0n, observedAt: now }, ...result };
  let snap = portfolioSnapshot(balances, parsePrices({ coins: coins() }, now), now, withBoth);
  assert.equal(snap.complete, true); assert.equal(snap.total, 0n); assert.equal(snap.state, 'complete');
  let row = snap.rows.find(r => r.key === 'ixios:IXIOS');
  assert.equal(row.balance, '7.25'); assert.equal(row.usd, null); assert.equal(row.priceMissing, false); assert.equal(usdText(row.usd), '—');
  const grouped = groupAssets(snap.rows);
  assert.deepEqual(grouped.slice(-2).map(g => g.symbol), ['CPUNK', 'IXIOS']);
  const ixios = grouped.find(g => g.symbol === 'IXIOS');
  assert.equal(ixios.balance, '7.25'); assert.equal(ixios.usd, null); assert.equal(usdText(ixios.usd), '—');
  assert.deepEqual(groupAssets(snap.rows, 'ixios').map(g => g.symbol), ['IXIOS']);
  // An IXIOS read failure (for example a wrong-network RPC) does not block
  // completeness of the priced portfolio, and does not become a zero balance.
  balances['ixios:IXIOS'] = { state: 'error' };
  snap = portfolioSnapshot(balances, parsePrices({ coins: coins() }, now), now, withBoth);
  row = snap.rows.find(r => r.key === 'ixios:IXIOS');
  assert.equal(snap.complete, true); assert.equal(row.state, 'error'); assert.equal(row.balance, null); assert.equal(row.usd, null);
});
test('NODUS is listed first but never read: an unsupported row takes no part in the load state, totals or completeness', () => {
  assert.deepEqual(NODUS_ASSET, { chain: 'nodus', symbol: 'NODUS', decimals: 8, key: 'nodus:NODUS' });
  assert.equal(NODUS_NETWORK.symbol, NODUS_ASSET.symbol); assert.equal(NODUS_NETWORK.icon, 'nodus.svg');
  assert.equal(NODUS_NETWORK.receiveOnly, true); assert.equal(NODUS_NETWORK.balanceUnavailable, true);
  assert.equal(NODUS_NETWORK.endpoint, undefined); assert.equal(NODUS_NETWORK.rpcOptions, undefined); assert.deepEqual(NODUS_NETWORK.tokens, []);
  assert.equal(NODUS_NETWORK.sendNote, 'Sending NODUS is not available in this release.');
  assert.ok(!/nodus/i.test(PRICE_URL));
  // The asset as portfolio-view.js merges it for a balanceUnavailable network.
  const nodus = { ...NODUS_ASSET, balanceUnavailable: true };
  const withNodus = [nodus, ...ASSETS, CPUNK_ASSET];
  // Every other row idle: the portfolio stays 'idle', not 'partial' or 'loading'.
  let snap = portfolioSnapshot({}, {}, now, withNodus);
  assert.equal(snap.state, 'idle');
  let row = snap.rows.find(r => r.key === 'nodus:NODUS');
  assert.equal(row.state, 'unsupported'); assert.equal(row.balance, null); assert.equal(row.usd, null); assert.equal(row.priceMissing, false);
  // Whatever `balances` holds for it (a refresh marks every asset 'loading'), the row stays unsupported.
  snap = portfolioSnapshot({ 'nodus:NODUS': { state: 'loading' } }, {}, now, withNodus);
  assert.equal(snap.state, 'idle'); assert.equal(snap.rows.find(r => r.key === 'nodus:NODUS').state, 'unsupported');
  // Every other row read: complete, the same total and counters as without the NODUS row.
  const balances = { ...ready(), 'cellframe:CPUNK': { state: 'ready', units: 0n, observedAt: now }, 'nodus:NODUS': { state: 'ready', units: 10n ** 8n, observedAt: now } };
  balances['ethereum:ETH'].units = 10n ** 18n;
  const quotes = parsePrices({ coins: coins() }, now);
  snap = portfolioSnapshot(balances, quotes, now, withNodus);
  const without = portfolioSnapshot(balances, quotes, now, [...ASSETS, CPUNK_ASSET]);
  assert.equal(snap.state, 'complete'); assert.equal(snap.complete, true); assert.equal(snap.total, 200000000n);
  for (const field of ['state', 'complete', 'total', 'known', 'positive', 'missingBalances', 'missingPrices']) assert.equal(snap[field], without[field], field);
  row = snap.rows.find(r => r.key === 'nodus:NODUS');
  assert.equal(row.state, 'unsupported'); assert.equal(row.balance, null); assert.equal(row.usd, null);
  // A failed priced read still reports 'partial', unaffected by the NODUS row.
  balances['solana:SOL'] = { state: 'error' };
  snap = portfolioSnapshot(balances, quotes, now, withNodus);
  assert.equal(snap.state, 'partial'); assert.equal(snap.missingBalances, 1);
  // Grouping: NODUS first, no balance and no USD value ('—').
  const grouped = groupAssets(snap.rows);
  assert.equal(grouped[0].symbol, 'NODUS'); assert.equal(grouped[0].balance, null); assert.equal(grouped[0].usd, null); assert.equal(usdText(grouped[0].usd), '—');
  assert.deepEqual(groupAssets(snap.rows, 'nodus').map(g => g.symbol), ['NODUS']);
  // Registry unchanged: NODUS is not one of the 14 priced ASSETS.
  assert.equal(ASSETS.length, 14); assert.ok(!ASSETS.some(a => a.chain === 'nodus'));
});
test('price requests contain only pinned asset identifiers and honor cancellation', async () => {
  let called=false;
  await readPrices({fetcher:async (url,options)=>{
    called=true;assert.equal(url,PRICE_URL);assert.equal(options.method,'GET');assert.equal(options.body,undefined);assert.equal(options.credentials,'omit');
    return new Response(JSON.stringify({coins:{}}));
  }});assert.equal(called,true);
  const controller=new AbortController();controller.abort();
  await assert.rejects(readPrices({signal:controller.signal,fetcher:()=>{throw new Error('Must not fetch');}}),/cancelled/);
});
