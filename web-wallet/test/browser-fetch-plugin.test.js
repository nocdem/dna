// Parent packaging equivalence gate. Execute the pinned dependency's original
// browser branch and transformed bundle source with the same mocked transport.
// No HTTP, files written, skip or private material; does not prove live RPCs.
import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { parseAst } from 'rollup/parseAst';
import { browserFetchPlugin } from '../scripts/browser-fetch-plugin.mjs';
const path=createRequire(import.meta.url).resolve('micro-ftch'),source=readFileSync(path,'utf8');
const plugin=browserFetchPlugin(),context={parse:parseAst,error(message){throw new Error(message);}};
const transformed=plugin.transform.call(context,source,path).code;
function declaration(code,name){const n=parseAst(code).body.find(n=>n.type==='FunctionDeclaration'&&n.id.name===name);return n&&code.slice(n.start,n.end);}
async function exercise(code,options,status=200,body='{"ok":true}',processValue){
  const calls=[],exports={};
  vm.runInNewContext(code,{exports,TextDecoder,Uint8Array,Headers,URL,btoa,process:processValue,
    require(){throw new Error('Node transport must not execute');},
    async fetch(url,opts){calls.push({url,...opts,headers:Object.fromEntries(opts.headers)});return new Response(body,{status,headers:{'content-type':'application/json','x-test':'public'}});}});
  try {const result=await exports.default('https://public:fixture@example.invalid/test',options);return JSON.parse(JSON.stringify({calls,result}));}
  catch(error){return JSON.parse(JSON.stringify({calls,error:{name:error.name,message:error.message,statusCode:error.statusCode}}));}
}
test('browser-only transform preserves exact upstream browser function and errors, rejects source drift',()=>{
  for(const name of ['fetchBrowser','fetchUrl','detectType'])assert.equal(declaration(transformed,name),declaration(source,name));
  assert.equal(declaration(transformed,'fetchNode'),undefined);
  assert.throws(()=>plugin.transform.call(context,source+'\n',path),/source hash/);
  assert.equal(plugin.transform.call(context,source,path+'.other'),undefined);
});
test('original browser branch and hash-pinned transformed dependency have equivalent requests, replies and errors',async()=>{
  const cases=[ [{type:'json'}], [{type:'json',full:true,data:{a:1},cors:true,headers:{'x-public':'yes','Cookie':'blocked'}},200,'{"value":2}'],
    [{type:'text',redirect:false,headers:{Accept:'text/plain'}},200,'hello'], [{type:'json'},503,'unavailable'], [{type:'json'},200,'not json'] ];
  for(const [options,status,body] of cases) {
    const expected=await exercise(source,options,status,body,undefined);
    assert.deepEqual(await exercise(transformed,options,status,body,{versions:{node:'public-fixture',v8:'public-fixture'}}),expected);
  }
});
