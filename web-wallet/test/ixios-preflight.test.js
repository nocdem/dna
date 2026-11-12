import test from 'node:test';import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';import {readIxiosPreflight,recheckIxiosPreflight,recheckIxiosReplay,ixiosMinimumGasPrice,IXIOS_RPC} from '../src/pq/ixios/preflight.js';import {IXIOS_GENESIS_HASH} from '../src/pq/ixios/balance.js';
const v=JSON.parse(readFileSync(new URL('./ixios-reference/vectors.json',import.meta.url)))[0],from=v.sender,to='0x'+v.to,now='0x'+Date.now().toString(16),tip={number:'0x1ee62ac',hash:'0x'+'ab'.repeat(32),timestamp:now};
function mock(change={}){let calls=[];return {calls,fetcher:async(url,options)=>{assert.equal(url,new URL(IXIOS_RPC).href);const q=JSON.parse(options.body);calls.push(q);let r;if(q.method==='eth_getBlockByNumber')r=q.params[0]==='0x1'?{number:'0x1',parentHash:IXIOS_GENESIS_HASH}:tip;else if(q.method==='eth_chainId')r='0x1';else if(q.method==='eth_getTransactionCount')r='0x7';else if(q.method==='eth_getBalance')r='0x'+(1000000n*10n**18n).toString(16);else if(q.method==='eth_gasPrice')r='0x'+93000000000000000n.toString(16);else if(q.method==='eth_getCode')r='0x';else if(q.method==='eth_estimateGas')r='0x3e8';else throw Error(q.method);if(change[q.method])r=change[q.method](q,r);return Response.json({jsonrpc:'2.0',id:q.id,result:r});}};}
test('Ixios preflight genesis, fork, fee, EOA and pending nonce are bound',async()=>{const m=mock(),r=await readIxiosPreflight({from,to,amount:123456789n,maxGasPrice:93000000000000000n,fetcher:m.fetcher});assert.equal(r.nonce,7n);assert.equal(r.gasLimit,1000n);assert.equal(r.fee,93000000000000000000n);assert.ok(m.calls.every(x=>!['eth_sendRawTransaction','eth_call'].includes(x.method)));assert.equal((await recheckIxiosPreflight(r,{fetcher:m.fetcher})).nonce,7n);});
test('Ixios rejects wrong genesis, unforked/stale tip, nonce ambiguity, code, bad gas, cap and unsafe quantities',async()=>{const cases=[{eth_getBlockByNumber:(q,r)=>q.params[0]==='0x1'?{...r,parentHash:'0x'+'00'.repeat(32)}:r},{eth_getBlockByNumber:(q,r)=>q.params[0]==='latest'?{...r,number:'0x1'}:r},{eth_getTransactionCount:(q,r)=>q.params[1]==='pending'?'0x8':r},{eth_getCode:()=> '0x01'},{eth_estimateGas:()=> '0x3e9'},{eth_gasPrice:()=> '0x'+93000000000000001n.toString(16)},{eth_getBalance:()=> '0x00'}];for(const c of cases)await assert.rejects(readIxiosPreflight({from,to,amount:123456789n,maxGasPrice:93000000000000000n,fetcher:mock(c).fetcher}));});
test('Ixios review expiry, wrong addresses and abort fail closed',async()=>{const m=mock();await assert.rejects(readIxiosPreflight({from,to:'0x'+'aa'.repeat(20),amount:1n,maxGasPrice:1n,fetcher:m.fetcher}));assert.equal(m.calls.length,0);await assert.rejects(recheckIxiosPreflight({expiresAt:Date.now()-1}));const ac=new AbortController();ac.abort();await assert.rejects(readIxiosPreflight({from,to,amount:1n,maxGasPrice:1n,fetcher:m.fetcher,signal:ac.signal}));});

test('Ixios source-pinned post-Aegis zeta floor and replay tolerate pending nonce/quote changes',async()=>{assert.equal(ixiosMinimumGasPrice(32400000n),93000000000000000n);const m=mock({eth_getTransactionCount:(q,r)=>q.params[1]==='pending'?'0x8':r,eth_gasPrice:()=> '0x1'}),row={address:from,nonce:'7',gasPrice:'93000000000000000'};await recheckIxiosReplay(row,{fetcher:m.fetcher});assert.ok(!m.calls.some(q=>q.method==='eth_gasPrice'||q.params?.[1]==='pending'));await assert.rejects(recheckIxiosReplay({...row,gasPrice:'92999999999999999'},{fetcher:m.fetcher}),/below/);await assert.rejects(recheckIxiosReplay(row,{fetcher:mock({eth_getTransactionCount:()=> '0x8'}).fetcher}),/nonce advanced/);});
test('Ixios distinguishes invalid node floor from user cap exceedance',async()=>{const args={from,to,amount:123n,maxGasPrice:93000000000000000n};await assert.rejects(readIxiosPreflight({...args,fetcher:mock({eth_gasPrice:()=> '0x1'}).fetcher}),/below the protocol minimum/);await assert.rejects(readIxiosPreflight({...args,maxGasPrice:92999999999999999n,fetcher:mock().fetcher}),/exceeds the approved cap/);});

// ---- Ixios test network: added with the test-network entry ----
// What this proves: with {networkId:'testnet'} the whole review (readIxiosPreflight, recheckIxiosPreflight,
// recheckIxiosReplay) talks to https://nx-rpc.ixoflow.io only, with ixios_ names only (no eth_ name), requires chain id
// 0x3 and the test genesis, uses Aegis 300 and the 10^17 gas floor at height 36,000, and decides "empty-code accounts
// only" from ixios_getProof's codeHash (zero hash or EmptyCodeHash accepted, another hash refused, a malformed answer
// or a wrong address refused; the request is [address, [], 'latest']); the result carries networkId. The main entry in
// the same process keeps today's request sequence (eth_ names, eth_getCode twice, no getProof).
// Compile flags / environment: none. Leaves nothing behind.
// Falsely passes if: the fetch stub did not assert URL and namespace (it does, on every request, and answers only the
// methods of the entry's list, so an eth_ name on the test entry throws); the stub answers getProof for any address
// (the answer echoes the requested address, and the wrong-address case alters it).
// Mocks prove wiring only; the real answer shapes of the live node are covered by the orchestrator's read-only check.
const TEST_URL = new URL('https://nx-rpc.ixoflow.io').href, MAIN_URL = new URL(IXIOS_RPC).href;
const TEST_GENESIS = '0x33177fd0b2fb50907e5f6e17af05b3812881ab2d3effbf0a3493d9b665dfa5fe';
const EMPTY_CODE = '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470', ZERO_CODE = '0x' + '00'.repeat(32);
const FLOOR_17 = 10n ** 17n;
// A scripted node for one entry. `change[name]` (name without the namespace) may alter an answer.
function netMock(kind, change = {}) {
  const test_ = kind === 'testnet', url = test_ ? TEST_URL : MAIN_URL, ns = test_ ? 'ixios' : 'eth', calls = [];
  const tipNumber = test_ ? '0x' + (36000).toString(16) : tip.number;
  return {
    calls,
    fetcher: async (u, options) => {
      assert.equal(u, url);
      const q = JSON.parse(options.body); calls.push(q);
      if (!q.method.startsWith(ns + '_')) throw Error(`wrong namespace for ${kind}: ${q.method}`);
      const name = q.method.slice(ns.length + 1);
      let r;
      if (name === 'getBlockByNumber') r = q.params[0] === '0x1' ? { number: '0x1', parentHash: test_ ? TEST_GENESIS : IXIOS_GENESIS_HASH } : { ...tip, number: tipNumber };
      else if (name === 'chainId') r = test_ ? '0x3' : '0x1';
      else if (name === 'getTransactionCount') r = '0x7';
      else if (name === 'getBalance') r = '0x' + (1000000n * 10n ** 18n).toString(16);
      else if (name === 'gasPrice') r = '0x' + (test_ ? FLOOR_17 : 93000000000000000n).toString(16);
      else if (name === 'getCode' && !test_) r = '0x';
      else if (name === 'getProof' && test_) { assert.deepEqual(q.params[1], []); assert.equal(q.params[2], 'latest'); r = { address: q.params[0], codeHash: EMPTY_CODE, balance: '0x0', nonce: '0x0', accountProof: [], storageHash: ZERO_CODE, storageProof: [] }; }
      else if (name === 'estimateGas') r = '0x3e8';
      else throw Error(`unexpected ${q.method}`);
      if (change[name]) r = change[name](q, r);
      return Response.json({ jsonrpc: '2.0', id: q.id, result: r });
    },
  };
}
const testArgs = { from, to, amount: 123456789n, maxGasPrice: FLOOR_17, networkId: 'testnet' };
const MAIN_SEQUENCE = ['eth_getBlockByNumber', 'eth_chainId', 'eth_getBlockByNumber', 'eth_getTransactionCount', 'eth_getTransactionCount', 'eth_getBalance', 'eth_gasPrice', 'eth_getCode', 'eth_getCode', 'eth_estimateGas', 'eth_getBlockByNumber', 'eth_chainId', 'eth_getBlockByNumber'];
test('test entry preflight: ixios_ names only, test URL only, chain 0x3, getProof for both accounts, networkId in the result', async () => {
  const m = netMock('testnet'), r = await readIxiosPreflight({ ...testArgs, fetcher: m.fetcher });
  assert.equal(r.networkId, 'testnet'); assert.equal(r.nonce, 7n); assert.equal(r.gasLimit, 1000n); assert.equal(r.gasPrice, FLOOR_17); assert.equal(r.fee, 1000n * FLOOR_17);
  assert.ok(m.calls.length > 0 && m.calls.every(q => q.method.startsWith('ixios_')), m.calls.map(q => q.method).join());
  assert.deepEqual(m.calls.map(q => q.method), MAIN_SEQUENCE.map(x => x.replace('eth_', 'ixios_').replace('getCode', 'getProof')));
  const proofs = m.calls.filter(q => q.method === 'ixios_getProof');
  assert.deepEqual(proofs.map(q => q.params).sort((a, b) => a[0] < b[0] ? -1 : 1), [[from, [], 'latest'], [to, [], 'latest']].sort((a, b) => a[0] < b[0] ? -1 : 1));
  assert.ok(m.calls.every(x => !['ixios_sendRawTransaction', 'ixios_call'].includes(x.method)));
  assert.deepEqual(m.calls.find(q => q.method === 'ixios_estimateGas').params, [{ from, to, value: '0x' + (123456789n).toString(16), gasPrice: '0x' + FLOOR_17.toString(16) }]);
  assert.equal((await recheckIxiosPreflight(r, { fetcher: m.fetcher })).nonce, 7n);
  assert.equal((await recheckIxiosPreflight(r, { fetcher: m.fetcher })).networkId, 'testnet');
});
test('main entry preflight keeps today\'s request sequence and carries networkId mainnet; main then test then main in one process', async () => {
  const a = netMock('mainnet'), ra = await readIxiosPreflight({ from, to, amount: 123456789n, maxGasPrice: 93000000000000000n, fetcher: a.fetcher });
  assert.deepEqual(a.calls.map(q => q.method), MAIN_SEQUENCE);
  assert.deepEqual(a.calls.filter(q => q.method === 'eth_getCode').map(q => q.params).sort((x, y) => x[0] < y[0] ? -1 : 1), [[from, 'latest'], [to, 'latest']].sort((x, y) => x[0] < y[0] ? -1 : 1));
  assert.equal(ra.networkId, 'mainnet');
  const t = netMock('testnet'); await readIxiosPreflight({ ...testArgs, fetcher: t.fetcher });
  const b = netMock('mainnet'), rb = await readIxiosPreflight({ from, to, amount: 123456789n, maxGasPrice: 93000000000000000n, networkId: 'mainnet', fetcher: b.fetcher });
  assert.deepEqual(b.calls.map(q => q.method), MAIN_SEQUENCE); assert.equal(rb.networkId, 'mainnet');
  assert.equal((await recheckIxiosPreflight(ra, { fetcher: netMock('mainnet').fetcher })).networkId, 'mainnet');
});
test('test entry refuses the wrong chain id, the main genesis, a tip below Aegis 300 + 12 and a stale tip', async () => {
  const cases = [
    { chainId: () => '0x1' },
    { getBlockByNumber: (q, r) => q.params[0] === '0x1' ? { ...r, parentHash: IXIOS_GENESIS_HASH } : r },
    { getBlockByNumber: (q, r) => q.params[0] === 'latest' ? { ...r, number: '0x137' } : r },
    { getBlockByNumber: (q, r) => q.params[0] === 'latest' ? { ...r, timestamp: '0x1' } : r },
  ];
  for (const c of cases) await assert.rejects(readIxiosPreflight({ ...testArgs, fetcher: netMock('testnet', c).fetcher }), /Wrong Ixios network|post-Aegis tip/);
  // 312 = 300 + 12 is the lowest accepted height.
  await assert.doesNotReject(readIxiosPreflight({ ...testArgs, fetcher: netMock('testnet', { getBlockByNumber: (q, r) => q.params[0] === 'latest' ? { ...r, number: '0x138' } : r }).fetcher }));
});
test('test entry: the gas floor is 10^17 at height 36,000 (quote below refused, cap exceeded refused), estimateGas must be 1000', async () => {
  await assert.rejects(readIxiosPreflight({ ...testArgs, fetcher: netMock('testnet', { gasPrice: () => '0x' + (FLOOR_17 - 1n).toString(16) }).fetcher }), /below the protocol minimum/);
  await assert.rejects(readIxiosPreflight({ ...testArgs, maxGasPrice: FLOOR_17 - 1n, fetcher: netMock('testnet').fetcher }), /exceeds the approved cap/);
  await assert.rejects(readIxiosPreflight({ ...testArgs, fetcher: netMock('testnet', { estimateGas: () => '0x3e9' }).fetcher }), /simple 1000-gas transfer/);
  await assert.rejects(readIxiosPreflight({ ...testArgs, fetcher: netMock('testnet', { getBalance: () => '0x00' }).fetcher }));
  await assert.rejects(readIxiosPreflight({ ...testArgs, fetcher: netMock('testnet', { getTransactionCount: (q, r) => q.params[1] === 'pending' ? '0x8' : r }).fetcher }), /unresolved pending nonce/);
  assert.equal(ixiosMinimumGasPrice(36000n, 300n), FLOOR_17);
  assert.equal(ixiosMinimumGasPrice(32400000n), 93000000000000000n);
  assert.throws(() => ixiosMinimumGasPrice(299n, 300n), /Aegis is not active/);
});
test('test entry: getProof codeHash decides empty-code accounts only', async () => {
  const proof = (address, codeHash) => ({ address, codeHash });
  for (const hash of [ZERO_CODE, EMPTY_CODE]) await assert.doesNotReject(readIxiosPreflight({ ...testArgs, fetcher: netMock('testnet', { getProof: q => proof(q.params[0], hash) }).fetcher }));
  const codeHash = '0x' + '11'.repeat(32);
  await assert.rejects(readIxiosPreflight({ ...testArgs, fetcher: netMock('testnet', { getProof: q => proof(q.params[0], codeHash) }).fetcher }), /empty-code accounts only/);
  // Only the recipient has code: still refused.
  await assert.rejects(readIxiosPreflight({ ...testArgs, fetcher: netMock('testnet', { getProof: q => proof(q.params[0], q.params[0] === to ? codeHash : EMPTY_CODE) }).fetcher }), /empty-code accounts only/);
  // Only the sender has code: refused as well.
  await assert.rejects(readIxiosPreflight({ ...testArgs, fetcher: netMock('testnet', { getProof: q => proof(q.params[0], q.params[0] === from ? codeHash : EMPTY_CODE) }).fetcher }), /empty-code accounts only/);
  for (const bad of [() => '0x', () => null, () => ({ codeHash: EMPTY_CODE }), q => proof('0x' + 'cd'.repeat(48), EMPTY_CODE), q => proof(q.params[0], '0x1234'), q => proof(q.params[0], undefined)]) {
    await assert.rejects(readIxiosPreflight({ ...testArgs, fetcher: netMock('testnet', { getProof: bad }).fetcher }), /Invalid Ixios account code/);
  }
});
test('test entry replay recheck: ixios_ names at the test URL, chain 0x3, the row\'s network, and the same refusals', async () => {
  const m = netMock('testnet', { getTransactionCount: (q, r) => q.params[1] === 'pending' ? '0x8' : r, gasPrice: () => '0x1' });
  const row = { address: from, nonce: '7', gasPrice: FLOOR_17.toString(), networkId: 'testnet' };
  const tipResult = await recheckIxiosReplay(row, { fetcher: m.fetcher });
  assert.equal(tipResult.height, 36000n);
  assert.deepEqual(m.calls.map(q => q.method), ['ixios_getBlockByNumber', 'ixios_chainId', 'ixios_getBlockByNumber', 'ixios_getTransactionCount']);
  assert.ok(m.calls.every(q => q.method.startsWith('ixios_')));
  assert.ok(!m.calls.some(q => q.method === 'ixios_gasPrice' || q.params?.[1] === 'pending'));
  await assert.rejects(recheckIxiosReplay({ ...row, gasPrice: (FLOOR_17 - 1n).toString() }, { fetcher: netMock('testnet').fetcher }), /below the current network floor/);
  await assert.rejects(recheckIxiosReplay(row, { fetcher: netMock('testnet', { getTransactionCount: () => '0x8' }).fetcher }), /nonce advanced/);
  // The same row read as a main row hits the main URL: the test stub refuses it (URL assert), proving the row's network is used.
  await assert.rejects(recheckIxiosReplay({ ...row, networkId: 'mainnet' }, { fetcher: netMock('testnet').fetcher }));
  await assert.rejects(recheckIxiosReplay({ ...row, networkId: 'regtest' }, { fetcher: netMock('testnet').fetcher }), /^Error: Unknown Ixios network\.$/);
});
test('an unknown network id makes no request in the preflight', async () => {
  const m = netMock('testnet');
  await assert.rejects(readIxiosPreflight({ ...testArgs, networkId: 'regtest', fetcher: m.fetcher }), /^Error: Unknown Ixios network\.$/);
  assert.equal(m.calls.length, 0);
  await assert.rejects(recheckIxiosPreflight({ from, to, amount: 1n, nonce: 7n, gasPrice: FLOOR_17, gasLimit: 1000n, networkId: 'regtest', expiresAt: Date.now() + 10000 }, { fetcher: m.fetcher }), /^Error: Unknown Ixios network\.$/);
  assert.equal(m.calls.length, 0);
});
