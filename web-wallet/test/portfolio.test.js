import test from 'node:test';
import assert from 'node:assert/strict';
import { ASSETS, PRICE_URL, BALANCE_MAX_AGE, PRICE_MAX_AGE, balanceUnits, chainBalances, parsePrices, readPrices, portfolioSnapshot, groupAssets, usdText } from '../src/portfolio.js';
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
test('price requests contain only pinned asset identifiers and honor cancellation', async () => {
  let called=false;
  await readPrices({fetcher:async (url,options)=>{
    called=true;assert.equal(url,PRICE_URL);assert.equal(options.method,'GET');assert.equal(options.body,undefined);assert.equal(options.credentials,'omit');
    return new Response(JSON.stringify({coins:{}}));
  }});assert.equal(called,true);
  const controller=new AbortController();controller.abort();
  await assert.rejects(readPrices({signal:controller.signal,fetcher:()=>{throw new Error('Must not fetch');}}),/cancelled/);
});
