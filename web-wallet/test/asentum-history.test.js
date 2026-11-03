import test from 'node:test';
import assert from 'node:assert/strict';
import { bech32 } from '@scure/base';
import { parseAsentumHistory, readAsentumHistory } from '../src/pq/asentum-history.js';
const bytes = Uint8Array.from({length:20}, (_,i) => i + 1);
const account = bech32.encode('ase', bech32.toWords(bytes));
const hex = '0x' + Buffer.from(bytes).toString('hex');
const other = '0x' + 'ab'.repeat(20);
const tx = {hash:'0x'+'ab'.repeat(32), from_addr:hex, to_addr:other, value:'1234567890123456789', timestamp:42, status:1};
const response = rows => ({rows,total:rows.length,page:1,size:50});
test('Asentum indexed transfers are validated and formatted exactly', () => {
  const [row] = parseAsentumHistory(response([tx,tx]),account);
  assert.equal(row.amount,'1.234567890123456789'); assert.equal(row.dir,'out'); assert.equal(row.time,42000);
  assert.equal(parseAsentumHistory(response([tx,tx]),account).length,1);
  assert.deepEqual(parseAsentumHistory(response([{...tx,status:null},{...tx,hash:'0x'+'cd'.repeat(32),from_addr:other},{...tx,hash:'0x'+'ef'.repeat(32),value:'1e3'}]),account),[]);
  assert.throws(() => parseAsentumHistory({rows:[]},account));
});
test('Asentum history pins node chain before querying official indexer', async () => {
  const urls=[]; const fetcher=async url => { urls.push(url); let data;
    if (url.endsWith('/chain')) data={chainId:'1423'};
    else if (url.endsWith('/genesis')) data={chainId:'1423',genesisHash:'0xc12243eee53d0a642c34845575687144802b79eabb07b213815ee907f0451aa3'};
    else data=response([tx]);
    return new Response(JSON.stringify(data),{status:200,headers:{'content-type':'application/json'}});
  };
  assert.equal((await readAsentumHistory(account,{fetcher})).length,1);
  assert.match(urls[2],/explorer\.asentum\.com\/api\/indexer\/address\//);
});
test('conflicting duplicate hashes fail closed, identical self-transfer rows deduplicate', () => {
  assert.throws(() => parseAsentumHistory(response([tx,{...tx,value:'2'}]),account), /Conflicting/);
  assert.throws(() => parseAsentumHistory(response([tx,{...tx,status:0}]),account), /Conflicting/);
  assert.equal(parseAsentumHistory(response([{...tx,to_addr:hex},{...tx,to_addr:hex}]),account).length,1);
});
test('wrong chain or abort prevents indexer access', async () => {
  let calls=0; const fetcher=async () => { calls++; return new Response(JSON.stringify({chainId:'wrong'}),{status:200}); };
  await assert.rejects(readAsentumHistory(account,{fetcher}),/wrong network/); assert.equal(calls,2);
  const controller=new AbortController(); controller.abort(); calls=0;
  await assert.rejects(readAsentumHistory(account,{fetcher,signal:controller.signal})); assert.equal(calls,0);
});
test('abort after a provider response prevents subsequent requests', async () => {
  const controller = new AbortController(); let calls=0;
  const fetcher=async () => { calls++; controller.abort(); return new Response(JSON.stringify({chainId:'1423'}),{status:200}); };
  await assert.rejects(readAsentumHistory(account,{fetcher,signal:controller.signal}));
  assert.equal(calls,1);
});
test('a malformed duplicate cannot hide a conflicting transaction', () => {
  assert.throws(() => parseAsentumHistory(response([tx,{...tx,status:null}]),account), /Conflicting/);
});
