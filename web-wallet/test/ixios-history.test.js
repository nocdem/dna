import test from 'node:test';import assert from 'node:assert/strict';import{readIxiosRecentNativeHistory}from'../src/pq/ixios/history.js';import{IXIOS_GENESIS_HASH}from'../src/pq/ixios/balance.js';
const own='0x'+'11'.repeat(48),peer='0x'+'22'.repeat(48),other='0x'+'33'.repeat(48),n=x=>'0x'+BigInt(x).toString(16),hash=c=>'0x'+c.repeat(64),start=32400000,endpoint='https://ixios-rpc.innova.limited';
function setup(){let mode='ok',headReads=0;const calls=[],blocks=new Map(),times=1700000000000;const h=(height)=>({number:n(height),hash:hash(height===start-1?'a':height===start?'b':'c'),parentHash:hash(height===start-1?'d':height===start?'a':'b'),timestamp:n(times+(height-start+1)*1000)});const tx=(c,from,to,value,input='0x')=>({hash:hash(c),blockHash:hash('b'),blockNumber:n(start),transactionIndex:n(c==='1'?0:c==='2'?1:2),from,to,value:n(value),input});blocks.set(start-1,h(start-1));blocks.set(start,{...h(start),transactions:[tx('1',own,peer,1234567890123456789n),tx('2',peer,own,100n),tx('3',other,peer,1n,'0x1234')]});blocks.set(start+1,{...h(start+1),transactions:[]});const call=async(url,method,params)=>{calls.push([url,method,params]);if(method==='eth_getBlockByNumber'){if(params[0]==='0x1')return {number:'0x1',parentHash:mode==='wrong-genesis'?hash('f'):IXIOS_GENESIS_HASH};if(params[0]==='latest')return h(start+1);const height=Number(BigInt(params[0]));if(height===start+1&&!params[1]){headReads++;if(mode==='reorg'&&headReads===2)return {...h(height),hash:hash('f')};if(mode==='scan-reorg'&&headReads===1)return {...h(height),hash:hash('f')};return h(height);}const b=structuredClone(blocks.get(height));if(mode==='parent'&&height===start)b.parentHash=hash('f');if(mode==='duplicate'&&height===start)b.transactions[1].hash=b.transactions[0].hash;if(mode==='oversize'&&height===start)b.transactions=new Array(501).fill(null);return b;}if(method==='eth_getCode')return mode==='contract'?'0x00':'0x';if(method==='eth_getTransactionReceipt'){const t=blocks.get(start).transactions.find(x=>x.hash===params[0]);return {transactionHash:t.hash,blockHash:mode==='bad-receipt'?hash('f'):t.blockHash,blockNumber:t.blockNumber,transactionIndex:t.transactionIndex,from:t.from,to:t.to,contractAddress:null,status:t.hash===hash('2')?'0x0':'0x1'};}throw Error('Unexpected RPC');};return {call,calls,mode:x=>mode=x,headReads:()=>headReads};}
test('bounded post-Aegis direct history uses exact bigint, milliseconds, receipts and stable head',async()=>{const x=setup(),r=await readIxiosRecentNativeHistory(own,{endpoint,startHeight:start,endHeight:start+1,call:x.call});assert.equal(r.rows.length,2);const good=r.rows.find(z=>z.status==='included'),failed=r.rows.find(z=>z.status==='failed');assert.equal(good.amount,'1.234567890123456789');assert.equal(good.time,1700000001000);assert.equal(good.direction,'out');assert.equal(failed.amount,'0.0');assert.equal(failed.attemptedAmount,'0.0000000000000001');assert.equal(failed.direction,'in');assert.match(r.status,/not complete or inclusion-proven/);assert.equal(x.headReads(),2);assert.ok(x.calls.every(([url])=>url===endpoint));assert.equal(x.calls.filter(([,method])=>method==='eth_getTransactionReceipt').length,2);});
test('rejects wrong identity, unstable chain, malformed receipts and overlarge ranges',async()=>{for(const [mode,pattern]of [['wrong-genesis',/wrong network/],['parent',/continuity/],['reorg',/head changed/],['scan-reorg',/range changed/],['duplicate',/Duplicate/],['oversize',/bound/],['bad-receipt',/Conflicting/]]){const x=setup();x.mode(mode);await assert.rejects(readIxiosRecentNativeHistory(own,{endpoint,startHeight:start,endHeight:start+1,call:x.call}),pattern);}const x=setup();await assert.rejects(readIxiosRecentNativeHistory(own,{endpoint,startHeight:start,endHeight:start+50,call:x.call}),/range/);await assert.rejects(readIxiosRecentNativeHistory(own,{endpoint,startHeight:start-1,endHeight:start,call:x.call}),/range/);});
test('skips persistent contract recipients and aborts without returning partial history',async()=>{const x=setup();x.mode('contract');const result=await readIxiosRecentNativeHistory(own,{endpoint,startHeight:start,endHeight:start+1,call:x.call});assert.equal(result.rows.length,0);assert.equal(x.calls.filter(([,m])=>m==='eth_getTransactionReceipt').length,0);const controller=new AbortController(),y=setup(),call=async(...args)=>{const result=await y.call(...args);if(args[1]==='eth_getCode')controller.abort();return result;};await assert.rejects(readIxiosRecentNativeHistory(own,{endpoint,startHeight:start,endHeight:start+1,signal:controller.signal,call}));});

test('explicit historical end is rechecked separately from the current head',async()=>{const x=setup(),r=await readIxiosRecentNativeHistory(own,{endpoint,startHeight:start,endHeight:start,call:x.call});assert.equal(r.endHeight,start);assert.ok(x.calls.some(([,method,p])=>method==='eth_getBlockByNumber'&&p[0]===n(start)&&p[1]===false));assert.equal(x.headReads(),1);});

// ---- Ixios test network: added with the test-network entry ----
// What this proves: with {networkId:'testnet'} the history read uses ixios_ names only at the test URL, takes the test
// genesis and Aegis 300 (the latest window starts at 300 at the lowest, a range below 300 is refused, a head below 300 is
// refused), and decides "no code at both adjacent heights" from ixios_getProof's codeHash at height-1 and height
// (request [address, [], block]); a recipient with code at either height is skipped; a malformed or wrong-address answer
// throws. The main entry in the same process keeps eth_getCode (four calls for two matching transactions, no getProof).
// Compile flags / environment: none (the `call` stub is the injected transport). Leaves nothing behind.
// Falsely passes if: the stub answered any method name (it throws on every method outside the entry's list and records the
// URL it was given, which is asserted), or the chain were so short that Aegis never bound the window (the head is 310, so
// the default window 291..310 is cut to 300..310 only by Aegis).
const TEST_ENDPOINT = 'https://nx-rpc.ixoflow.io', TEST_GENESIS = '0x33177fd0b2fb50907e5f6e17af05b3812881ab2d3effbf0a3493d9b665dfa5fe';
const EMPTY_CODE = '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470', CODE = '0x' + '11'.repeat(32);
function testNode({ head = 310, codeAt = () => EMPTY_CODE, proofAddress = a => a, genesis = TEST_GENESIS } = {}) {
  const calls = [], at = h => '0x' + BigInt(h).toString(16).padStart(64, '0');
  const txs = [{ hash: hash('1'), from: own, to: peer, value: n(1234567890123456789n), input: '0x' }, { hash: hash('2'), from: peer, to: own, value: n(100n), input: '0x' }, { hash: hash('3'), from: other, to: peer, value: n(1n), input: '0x1234' }];
  const block = (h, full) => ({ number: n(h), hash: at(h), parentHash: at(h - 1), timestamp: n(1700000000000 + h * 1000), transactions: h === 300 && full ? txs.map((t, i) => ({ ...t, blockHash: at(300), blockNumber: n(300), transactionIndex: n(i) })) : [] });
  const call = async (url, method, params) => {
    calls.push([url, method, params]);
    if (method === 'ixios_getBlockByNumber') { if (params[0] === '0x1') return { number: '0x1', parentHash: genesis }; if (params[0] === 'latest') return block(head, false); return block(Number(BigInt(params[0])), params[1]); }
    if (method === 'ixios_getProof') return { address: proofAddress(params[0]), codeHash: codeAt(params[0], Number(BigInt(params[2]))) };
    if (method === 'ixios_getTransactionReceipt') { const i = txs.findIndex(t => t.hash === params[0]); return { transactionHash: params[0], blockHash: at(300), blockNumber: n(300), transactionIndex: n(i), from: txs[i].from, to: txs[i].to, contractAddress: null, status: i === 1 ? '0x0' : '0x1' }; }
    throw Error(`Unexpected RPC ${method}`);
  };
  return { call, calls };
}
const byAddress = (a, b) => (a[0] + a[2]) < (b[0] + b[2]) ? -1 : 1;
test('test entry history: ixios_ names at the test URL, Aegis 300, getProof at height-1 and height for each matching transaction', async () => {
  const x = testNode(), r = await readIxiosRecentNativeHistory(own, { networkId: 'testnet', startHeight: 300, endHeight: 301, call: x.call });
  assert.equal(r.rows.length, 2); assert.equal(r.startHeight, 300); assert.equal(r.endHeight, 301);
  assert.deepEqual(r.rows.map(row => row.hash).sort(), [hash('1'), hash('2')].sort());
  assert.ok(x.calls.length > 0 && x.calls.every(([url, method]) => url === TEST_ENDPOINT && method.startsWith('ixios_')), x.calls.map(c => c[0] + ' ' + c[1]).join());
  assert.deepEqual(x.calls.filter(([, m]) => m === 'ixios_getProof').map(([, , p]) => p).sort(byAddress), [[own, [], n(299)], [own, [], n(300)], [peer, [], n(299)], [peer, [], n(300)]].sort(byAddress));
  assert.ok(x.calls.some(([, m, p]) => m === 'ixios_getBlockByNumber' && p[0] === n(299) && p[1] === false), 'the anchor block is 299');
  assert.equal(x.calls.filter(([, m]) => m === 'ixios_getTransactionReceipt').length, 2);
});
test('test entry history: the latest window is cut at Aegis 300 (head 310, limit 20) and a head below 300 is refused', async () => {
  const x = testNode(), r = await readIxiosRecentNativeHistory(own, { networkId: 'testnet', call: x.call });
  assert.equal(r.startHeight, 300); assert.equal(r.endHeight, 310); assert.equal(r.rows.length, 2);
  assert.ok(x.calls.every(([url]) => url === TEST_ENDPOINT));
  const fetched = x.calls.filter(([, m, p]) => m === 'ixios_getBlockByNumber' && p[1] === true).map(([, , p]) => p[0]);
  assert.deepEqual(fetched, Array.from({ length: 11 }, (_, i) => n(300 + i)));
  await assert.rejects(readIxiosRecentNativeHistory(own, { networkId: 'testnet', call: testNode({ head: 299 }).call }), /post-Aegis history is unavailable/);
  await assert.rejects(readIxiosRecentNativeHistory(own, { networkId: 'testnet', startHeight: 299, endHeight: 300, call: testNode().call }), /Invalid Ixios history range/);
});
test('test entry history: a recipient with code at height-1 or at height is skipped; no receipt is read for it', async () => {
  for (const codeAt of [() => CODE, (a, h) => h === 300 ? CODE : EMPTY_CODE, (a, h) => h === 299 ? CODE : EMPTY_CODE]) {
    const x = testNode({ codeAt }), r = await readIxiosRecentNativeHistory(own, { networkId: 'testnet', startHeight: 300, endHeight: 301, call: x.call });
    assert.equal(r.rows.length, 0); assert.equal(x.calls.filter(([, m]) => m === 'ixios_getTransactionReceipt').length, 0);
  }
  const zero = testNode({ codeAt: () => '0x' + '00'.repeat(32) }), r = await readIxiosRecentNativeHistory(own, { networkId: 'testnet', startHeight: 300, endHeight: 301, call: zero.call });
  assert.equal(r.rows.length, 2, 'the zero hash (no account) counts as no code');
});
test('test entry history: wrong genesis, a wrong-address getProof answer and a malformed codeHash fail closed', async () => {
  await assert.rejects(readIxiosRecentNativeHistory(own, { networkId: 'testnet', startHeight: 300, endHeight: 301, call: testNode({ genesis: '0xa19acef59b3b84f192a69407981c50695fd105988d9311dd2e1c60332b629f2f' }).call }), /wrong network/);
  await assert.rejects(readIxiosRecentNativeHistory(own, { networkId: 'testnet', startHeight: 300, endHeight: 301, call: testNode({ proofAddress: () => '0x' + 'cd'.repeat(48) }).call }), /Invalid Ixios account code/);
  await assert.rejects(readIxiosRecentNativeHistory(own, { networkId: 'testnet', startHeight: 300, endHeight: 301, call: testNode({ codeAt: () => '0x1234' }).call }), /Invalid Ixios account code/);
  await assert.rejects(readIxiosRecentNativeHistory(own, { networkId: 'regtest', call: testNode().call }), /^Error: Unknown Ixios network\.$/);
});
test('main, test, main in one process: the main read keeps eth_getCode and its endpoint, the test read never uses an eth_ name', async () => {
  const run = async () => { const x = setup(), r = await readIxiosRecentNativeHistory(own, { endpoint, startHeight: start, endHeight: start + 1, call: x.call }); return { x, r }; };
  const a = await run();
  const t = testNode(); await readIxiosRecentNativeHistory(own, { networkId: 'testnet', startHeight: 300, endHeight: 301, call: t.call });
  const b = await run();
  for (const { x, r } of [a, b]) {
    assert.equal(r.rows.length, 2);
    assert.equal(x.calls.filter(([, m]) => m === 'eth_getCode').length, 4);
    assert.ok(x.calls.every(([url, m]) => url === endpoint && m.startsWith('eth_')));
  }
  assert.ok(t.calls.every(([, m]) => !m.startsWith('eth_')));
});
test('main entry with an explicit networkId and no endpoint reads the main endpoint (default endpoint follows the entry)', async () => {
  const x = setup(); await readIxiosRecentNativeHistory(own, { networkId: 'mainnet', startHeight: start, endHeight: start + 1, call: x.call });
  assert.ok(x.calls.every(([url]) => url === endpoint));
  const t = testNode(); await readIxiosRecentNativeHistory(own, { networkId: 'testnet', startHeight: 300, endHeight: 301, call: t.call });
  assert.ok(t.calls.every(([url]) => url === TEST_ENDPOINT), 'no endpoint given: the test entry\'s endpoint is used');
});
