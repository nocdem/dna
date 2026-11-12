import test from 'node:test';
import assert from 'node:assert/strict';
import { ASSETS, CPUNK_ASSET, PRICE_URL, BALANCE_MAX_AGE, PRICE_MAX_AGE, balanceUnits, chainBalances, balanceErrorDetail, unavailableBalanceLabel, parsePrices, readPrices, portfolioSnapshot, groupAssets, usdText, displayAmount } from '../src/portfolio.js';
import { IXIOS_NETWORK, IXIOS_ASSET } from '../src/pq/ixios/network.js';
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
  // Grouping (0.1.102): CPUNK sorts by its network's name among the coins
  // after the stablecoins — Cellframe after BNB Smart Chain, before Ethereum.
  const grouped = groupAssets(snap.rows, 'all', { bsc: 'BNB Smart Chain', cellframe: 'Cellframe', ethereum: 'Ethereum' });
  assert.deepEqual(grouped.slice(-5).map(g => g.symbol), ['BNB', 'CPUNK', 'ETH', 'SOL', 'TRX']); assert.equal(grouped.find(g => g.symbol === 'CPUNK').usd, null);
});
test('IXIOS is an unpriced, receive-only row like CPUNK: no priceId, no PRICE_URL entry, never counted in the USD total or completeness, sorts by its network name', () => {
  assert.equal(IXIOS_ASSET.priceId, undefined);
  assert.equal(IXIOS_ASSET.chain, 'ixios'); assert.equal(IXIOS_ASSET.key, 'ixios:IXIOS'); assert.equal(IXIOS_ASSET.decimals, 18);
  assert.equal(IXIOS_NETWORK.symbol, IXIOS_ASSET.symbol); assert.equal(IXIOS_NETWORK.icon, 'ixios.png');
  assert.equal(IXIOS_NETWORK.receiveOnly, true); assert.equal(Object.hasOwn(IXIOS_NETWORK, 'notActive'), false);
  assert.equal(IXIOS_NETWORK.endpoint, 'https://ixios-rpc.innova.limited');
  assert.deepEqual(IXIOS_NETWORK.rpcOptions, [{ url: IXIOS_NETWORK.endpoint, label: 'Ixios public RPC' }]); assert.deepEqual(IXIOS_NETWORK.tokens, []);
  assert.equal(IXIOS_NETWORK.sendNote, 'Send IXIOS from the extension.');
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
  const grouped = groupAssets(snap.rows, 'all', { bsc: 'BNB Smart Chain', cellframe: 'Cellframe', ethereum: 'Ethereum', ixios: 'Ixios', solana: 'Solana', tron: 'TRON' });
  assert.deepEqual(grouped.slice(-6).map(g => g.symbol), ['BNB', 'CPUNK', 'ETH', 'IXIOS', 'SOL', 'TRX'], 'by network name (0.1.102)');
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
  assert.deepEqual(NODUS_ASSET, { chain: 'nodus', symbol: 'NODUS', decimals: 8, key: 'nodus:NODUS', tokenId: '0'.repeat(128) });
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
  // 0.1.102 (operator): NODUS, then the stablecoins, then the other coins by
  // their network's name ("BNB Smart Chain", "Cellframe", "Ethereum", "Solana",
  // "TRON"); without names, by chain key.
  const names = { nodus: 'Nodus', ethereum: 'Ethereum', bsc: 'BNB Smart Chain', solana: 'Solana', tron: 'TRON', cellframe: 'Cellframe' };
  assert.deepEqual(groupAssets(snap.rows, 'all', names).map(g => g.symbol), ['NODUS', 'USDT', 'USDC', 'DAI', 'USDD', 'BNB', 'CPUNK', 'ETH', 'SOL', 'TRX']);
  assert.deepEqual(grouped.slice(0, 5).map(g => g.symbol), ['NODUS', 'USDT', 'USDC', 'DAI', 'USDD']);
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

test('balance display: thousands separators, at most 6 decimals truncated (never rounded up), dust shown as <0.000001', () => {
  assert.equal(displayAmount('20123456.123456789012345678'), '20,123,456.123456');
  assert.equal(displayAmount('0.999999999999999999'), '0.999999');          // truncated, not rounded to 1
  assert.equal(displayAmount('0.000000000000000028'), '<0.000001');         // the "28 ETH" dust case
  assert.equal(displayAmount('1.5'), '1.5');
  assert.equal(displayAmount('1.500000'), '1.5');
  assert.equal(displayAmount('0.0'), '0');
  assert.equal(displayAmount('50000000.0'), '50,000,000');
  assert.equal(displayAmount('1234'), '1,234');
  assert.equal(displayAmount('not a number'), 'not a number');
});

// 0.1.113 (operator 2026-10-13: "Hiç olmayan … Kaç dolar olduğu değil, bir şey
// olup olmadığı önemli"): zero balances hidden by the AMOUNT, never by the
// dollar value; NODUS and rows not read stay.
test('zero balances: hidden by the amount; held unpriced assets, unread rows and NODUS stay; held networks only', () => {
  const row = (symbol, chain, fields) => ({ symbol, chain, decimals: 6, ...fields });
  const rows = [
    row('NODUS', 'nodus', { balance: '0', units: 0n, usd: null }),           // the wallet's own asset: stays at 0
    row('USDT', 'tron', { balance: '5', units: 5000000n, priceId: 'tether', usd: 5n }),
    row('USDT', 'ethereum', { balance: '0', units: 0n, priceId: 'tether', usd: 0n }), // held elsewhere: this network left out
    row('ETH', 'ethereum', { balance: '0', units: 0n, priceId: 'ethereum', usd: 0n }), // nothing held: left out
    row('SOL', 'solana', { balance: null, state: 'loading', usd: null }),     // not read yet: stays
    row('CPUNK', 'cellframe', { balance: '3', units: 3000000n, usd: null })    // held, no price: stays
  ];
  const shown = groupAssets(rows, 'all', {}, { hideZero: true });
  assert.deepEqual(shown.map(g => g.symbol).sort(), ['CPUNK', 'NODUS', 'SOL', 'USDT']);
  assert.deepEqual(shown.find(g => g.symbol === 'USDT').rows.map(r => r.chain), ['tron']);
  // Off (the default of groupAssets itself, and the "show" setting): everything.
  assert.deepEqual(groupAssets(rows).map(g => g.symbol).sort(), ['CPUNK', 'ETH', 'NODUS', 'SOL', 'USDT']);
  // A network filter whose only asset is zero gives an empty list (the page says so).
  assert.deepEqual(groupAssets(rows, 'ethereum', {}, { hideZero: true }), []);
});


test('unavailable sources and safe read errors retain a last balance without exposing provider text', () => {
  assert.equal(unavailableBalanceLabel('qtc'), 'No balance reader');
  assert.equal(unavailableBalanceLabel('nodus'), 'Nodus not ready');
  assert.equal(balanceErrorDetail(Object.assign(new Error('secret https://example.test/address'), { status: 503 })), 'HTTP 503');
  assert.equal(balanceErrorDetail(new Error('secret https://example.test/address')), 'Balance unavailable');
  assert.equal(balanceErrorDetail(new Error('RPC is connected to the wrong network.')), 'Wrong network');
  assert.equal(balanceErrorDetail(new Error('RPC is connected to the wrong network. secret')), 'Balance unavailable');
  const asset = { ...NODUS_ASSET, balanceUnavailable: true };
  let row = portfolioSnapshot({}, {}, now, [asset], { [asset.key]: { units: 125000000n, observedAt: now - 1000 } }).rows[0];
  assert.equal(row.state, 'unsupported'); assert.equal(row.balance, '1.25'); assert.equal(row.keptAt, now - 1000); assert.equal(row.usd, null);
  row = portfolioSnapshot({ [asset.key]: { state: 'error', error: 'HTTP 503' } }, {}, now, [NODUS_ASSET], { [asset.key]: { units: 125000000n, observedAt: now - 1000 } }).rows[0];
  assert.equal(row.balance, '1.25'); assert.equal(row.error, 'HTTP 503'); assert.equal(row.keptAt, now - 1000); assert.equal(row.usd, null);
  assert.equal(portfolioSnapshot({}, {}, now, [asset]).rows[0].balance, null);
});

// ---- Kept prices (operator 2026-11-12: show the last read total at once, replace as fresh reads arrive) ----
const ETH = ASSETS.find(asset => asset.key === 'ethereum:ETH'), UNITS = 15n * 10n ** 17n, PRICE = 200000000n * 1000n, PRICE_NEW = 250000000n * 1000n;
const valued = (units, price) => units * price / 10n ** 18n;

// Proves a kept balance with its kept price gives the total at once, from the kept values only (nothing read yet), with
// the oldest of the balance and price read times; the row is marked as a kept value. Could falsely pass if the total
// came from another asset: only the ETH entry is given, and the expected value is computed from its own numbers.
test('kept balances with kept prices give the total at once, with the last read time', () => {
  const kept = { 'ethereum:ETH': { units: UNITS, observedAt: now - 1000, address: '0xabc', price: { units: PRICE, observedAt: now - 5000 } } };
  const snap = portfolioSnapshot({}, {}, now, ASSETS, kept);
  const row = snap.rows.find(r => r.key === 'ethereum:ETH');
  assert.equal(snap.total, valued(UNITS, PRICE)); assert.equal(row.usd, valued(UNITS, PRICE)); assert.equal(row.keptUsd, true);
  assert.equal(snap.keptCount, 1); assert.equal(snap.keptAt, now - 5000); assert.equal(snap.positive, true);
});

// Proves the fresh reads replace the kept value: with a fresh balance and a fresh price the total is the fresh one and no
// kept row remains; with only a fresh price (balance still kept) the kept balance is valued at the fresh price. Could
// falsely pass if the kept value equalled the fresh one; the numbers differ (1.5 and 2 ETH, two prices).
test('fresh reads replace the kept total', () => {
  const kept = { 'ethereum:ETH': { units: UNITS, observedAt: now - 1000, address: '0xabc', price: { units: PRICE, observedAt: now - 5000 } } };
  const fresh = { 'ethereum:ETH': { state: 'ready', units: 2n * 10n ** 18n, observedAt: now } }, quote = { 'ethereum:ETH': { units: PRICE_NEW, observedAt: now } };
  const all = portfolioSnapshot(fresh, quote, now, ASSETS, kept);
  assert.equal(all.total, valued(2n * 10n ** 18n, PRICE_NEW)); assert.equal(all.keptCount, 0); assert.equal(all.keptAt, undefined);
  const priceOnly = portfolioSnapshot({}, quote, now, ASSETS, kept);
  assert.equal(priceOnly.total, valued(UNITS, PRICE_NEW)); assert.equal(priceOnly.keptCount, 1);
});

// Proves a kept balance whose price was never kept stays out of the total, as before: no total, no kept row counted, the
// row still shows its last read time. Could falsely pass if the asset were unpriced; ETH has a price identity.
test('a kept balance without a kept price stays out of the total', () => {
  const snap = portfolioSnapshot({}, {}, now, ASSETS, { 'ethereum:ETH': { units: UNITS, observedAt: now - 1000, address: '0xabc' } });
  const row = snap.rows.find(r => r.key === 'ethereum:ETH');
  assert.equal(snap.total, null); assert.equal(snap.keptCount, 0); assert.equal(row.usd, null); assert.equal(row.keptAt, now - 1000);
});

// Proves a kept balance with a kept price counts in the total only while that asset's fresh read is pending (idle or
// loading), and leaves it once the read has failed (the existing rule: a chain whose read fails is left out of the
// total); the failed row still shows its last read value and time. Could falsely pass if the kept entry carried no
// price; the pending cases assert the kept total first.
test('a kept value counts while its read is pending and leaves the total when the read fails', () => {
  const kept = { 'ethereum:ETH': { units: UNITS, observedAt: now - 1000, address: '0xabc', price: { units: PRICE, observedAt: now - 5000 } } };
  for (const state of [{ state: 'idle' }, { state: 'loading' }]) {
    const pending = portfolioSnapshot({ 'ethereum:ETH': state }, {}, now, ASSETS, kept);
    assert.equal(pending.total, valued(UNITS, PRICE), state.state); assert.equal(pending.keptCount, 1); assert.equal(pending.keptAt, now - 5000);
  }
  const failed = portfolioSnapshot({ 'ethereum:ETH': { state: 'error', error: 'Balance unavailable' } }, {}, now, ASSETS, kept);
  const row = failed.rows.find(r => r.key === 'ethereum:ETH');
  assert.equal(failed.total, null); assert.equal(failed.keptCount, 0); assert.equal(row.usd, null);
  assert.equal(row.balance, '1.5'); assert.equal(row.keptAt, now - 1000);
});
