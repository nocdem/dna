import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
test('PQ history environment is selected, checked, and excluded from legacy persistence', () => {
  const app = readFileSync(new URL('../src/app.js', import.meta.url), 'utf8');
  assert.match(app, /networkId: isPqChain\(chain\) \? pqSelections\[chain\] : undefined/);
  assert.match(app, /isPqChain\(chain\) && job.networkId !== pqSelections\[chain\]/);
  assert.match(app, /!isPqChain\(chain\) && h.address === source.addresses\[chain\]/);
  assert.match(app, /outgoing amounts include fees/);
});
test('QTC dispatcher and persistence gates agree', () => {
  const history = readFileSync(new URL('../src/history.js', import.meta.url), 'utf8');
  assert.match(history, /if \(chain === 'qtc'\) return await readQtcHistory\(address, \{ signal, networkId \}\)/);
  assert.match(history, /chain === 'algorand' \|\| chain === 'qtc' \|\| chain === 'xion' \|\| chain === 'splendor' \|\| !historySupported/);
});

test('partial XION/Splendor and QTC histories are routed on both wallet surfaces with network fences', () => {
 const history=readFileSync(new URL('../src/history.js',import.meta.url),'utf8');
 const screen=readFileSync(new URL('../extension/src/ui/wallet-screen.js',import.meta.url),'utf8');
 assert.match(history,/chain === 'xion'.*readXionHistory/);
 assert.match(history,/chain === 'splendor'.*readSplendorHistory/);
 assert.match(screen,/\['qtc', 'xion', 'splendor'\]\.includes\(chain\)/);
 assert.match(screen,/readPublicHistory\(chain, address, \{ networkId, signal: controller.signal \}\)/);
 assert.match(screen,/selectedNetwork\(chain\).id !== networkId/);
 assert.match(screen,/May be incomplete or stale; not inclusion proof/);
});
