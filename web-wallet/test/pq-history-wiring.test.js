import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
// Wiring pins by source text (src/app.js needs a DOM, so these are not behaviour): the PQ chains' pages are kept for a saved wallet
// (2026-11-14, device cache decision 2026-10-02) behind the per-chain saved-row check; the behaviour is in test/history-kept.test.js.
// Falsely passes if the text stayed but the code path were dead; the saved-row behaviour tests would then still pass, the browser run would not.
test('PQ history environment is selected, checked, and kept with a saved wallet', () => {
  const app = readFileSync(new URL('../src/app.js', import.meta.url), 'utf8');
  // The read's network: a PQ chain's selection, Ixios its own selection (2026-11-14), other networks none.
  assert.match(app, /const historyNetwork = chain => chain === ixiosChain \? ixiosSelection : isPqChain\(chain\) \? pqSelections\[chain\] : undefined;/);
  assert.match(app, /job = \{ chain, networkId: historyNetwork\(chain\),/);
  assert.match(app, /job.networkId !== historyNetwork\(chain\)\) return;/);
  assert.match(app, /h.networkId === historyNetwork\(chain\) \? h : null/);
  assert.match(app, /filter\(\(\[chain, h\]\) => historyAddressOk\(chain, h, source\)\)/);
  assert.match(app, /isPqChain\(chain\)\s*\? h.networkId !== undefined && \(pqAddresses\[chain\]\?\.\[h.networkId\] === undefined/);
  assert.doesNotMatch(app, /delete historyByChain\[chain\]/);
  assert.match(app, /outgoing amounts include fees/);
});
test('QTC dispatcher and persistence gates agree', () => {
  const history = readFileSync(new URL('../src/history.js', import.meta.url), 'utf8');
  assert.match(history, /if \(chain === 'qtc'\) return await readQtcHistory\(address, \{ signal, networkId \}\)/);
  assert.match(history, /if \(Object.hasOwn\(PQ_SAVED, chain\) && historySupported\(chain\)\) return checkPqRows\(chain, rows\);/);
  assert.match(history, /qtc: \{ hash: .*symbol: 'QTC'/);
});

test('partial XION/Splendor and QTC histories are routed on both wallet surfaces with network fences', () => {
 const history=readFileSync(new URL('../src/history.js',import.meta.url),'utf8');
 const screen=readFileSync(new URL('../extension/src/ui/wallet-screen.js',import.meta.url),'utf8');
 assert.match(history,/chain === 'xion'.*readXionHistory/);
 assert.match(history,/chain === 'splendor'.*readSplendorHistory/);
 // XION on every network goes through the background holder, which keeps the page (src/background/xion.js); QTC and Splendor keep the
 // direct branch (isSolanaTron answers for both before it, so it is not reached today).
 assert.match(screen,/else if \(chain === 'xion'\) \{ await ui\.loadSolanaTronHistory\(chain, \{ manual \}\); history = ui\.state\.solanaTronHistory\[chain\]; \}/);
 assert.match(screen,/\['qtc', 'splendor'\]\.includes\(chain\)/);
 assert.match(screen,/readPublicHistory\(chain, address, \{ networkId, signal: controller.signal \}\)/);
 assert.match(screen,/selectedNetwork\(chain\).id !== networkId/);
 assert.match(screen,/May be incomplete or stale; not inclusion proof/);
});
