// UPDATE NOTICE (web 0.1.129; design docs/plans/2026-10-20-update-required-
// warning-design.md §1 B): the module's compatibility answer, its parse, the
// banner decision and the banner itself.
//
// What each test proves:
//   - parseRulesetCompat accepts the module's shape and refuses any other
//     (an outcome outside 0/1/2, a non-decimal number, an "upcoming switch"
//     at or below the tip);
//   - updateNoticeOf: outcome 0 shows nothing; 2 is the "out of date"
//     notice (not dismissible, the numbers in the details line); 1 is the
//     upgrade notice with the block and the blocks left (dismissible);
//   - the banner (a minimal fake document): Reload only for outcome 2 and
//     it calls reload; Dismiss only for outcome 1, and a dismissed switch
//     stays hidden while another switch is shown; show(null) removes it;
//   - the client: rulesetCompat goes through the queue when the module has
//     it; a module without it still unlocks and reports compatReadable
//     false;
//   - with NODUS_SEND_PARITY_OUT: the module's C rule (nodus_ruleset_compat
//     through nsw_test_ri_compat -> nsw_ri_compat_json) gives 2 / 1 / 0 for
//     the boundary cases, with the module's own max generation. Without it
//     that test SKIPS (a skip is not a pass).
// What it does NOT prove: the real module's network path (no node), the
// banner inside the two real pages (src/app.js wiring; no browser here).
import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseRulesetCompat } from '../src/adapters/nodus.js';
import { updateNoticeOf, createUpdateNotice } from '../src/nodus/update-notice.js';
import { createNodusClient } from '../src/nodus/client.js';
import { createMockNodusModule, FINGERPRINT } from './nodus-mock-module.js';

const answer = over => ({ outcome: 0, generation: '5', nextGeneration: '0', nextHeight: '0', tip: '1000', maxGeneration: '5', ...over });

test('parseRulesetCompat: the module shape is accepted, everything else refused', () => {
  assert.deepEqual(parseRulesetCompat(answer()), { outcome: 0, generation: 5n, nextGeneration: 0n, nextHeight: 0n, tip: 1000n, maxGeneration: 5n });
  assert.equal(parseRulesetCompat(answer({ outcome: 2, generation: '6' })).generation, 6n);
  assert.equal(parseRulesetCompat(answer({ outcome: 1, nextGeneration: '6', nextHeight: '1001' })).nextHeight, 1001n);
  const refused = [
    null, answer({ outcome: 3 }), answer({ outcome: -1 }), answer({ outcome: '0' }),
    answer({ generation: 5 }), answer({ tip: '-1' }), answer({ nextHeight: '01' }), answer({ maxGeneration: '' }),
    answer({ tip: '18446744073709551616' }),
    answer({ outcome: 1, nextGeneration: '6', nextHeight: '1000' }),   // not above the tip
    answer({ outcome: 1, nextGeneration: '0', nextHeight: '2000' })    // no generation named
  ];
  for (const r of refused) assert.throws(() => parseRulesetCompat(r), /invalid/, JSON.stringify(r));
});

test('updateNoticeOf: 0 nothing, 2 out of date (not dismissible), 1 upcoming upgrade (dismissible)', () => {
  assert.equal(updateNoticeOf(null), null);
  assert.equal(updateNoticeOf(parseRulesetCompat(answer())), null);
  const req = updateNoticeOf(parseRulesetCompat(answer({ outcome: 2, generation: '6' })));
  assert.equal(req.level, 'required');
  assert.equal(req.dismissible, false);
  assert.equal(req.text, 'This page is out of date: the Nodus network now uses newer rules (generation 6). Reload the page to get the current version.');
  assert.equal(req.details, 'Network rules: generation 6 at block 1000. This page supports up to generation 5.');
  const up = updateNoticeOf(parseRulesetCompat(answer({ outcome: 1, nextGeneration: '6', nextHeight: '1720' })));
  assert.equal(up.level, 'upcoming');
  assert.equal(up.dismissible, true);
  assert.equal(up.text, 'A Nodus network upgrade happens at block 1720 (in about 720 blocks). This page will need to be reloaded after the update is published.');
  assert.equal(up.details, 'Network rules: generation 5 now, generation 6 from block 1720; current block 1000. This page supports up to generation 5.');
  assert.match(updateNoticeOf(parseRulesetCompat(answer({ outcome: 1, nextGeneration: '6', nextHeight: '1001' }))).text, /in about 1 block\)/);
  assert.notEqual(up.key, updateNoticeOf(parseRulesetCompat(answer({ outcome: 1, nextGeneration: '6', nextHeight: '1721' }))).key);
  // the main line carries no "rule-set" wording
  for (const n of [req, up]) assert.doesNotMatch(n.text, /rule-set/);
});

// A minimal document: enough of createElement / body.prepend for the banner.
function fakeDocument() {
  const make = tag => {
    const node = {
      tag, children: [], dataset: {}, attrs: {}, listeners: {}, textContent: '', parent: null,
      setAttribute(name, value) { node.attrs[name] = String(value); },
      addEventListener(type, fn) { node.listeners[type] = fn; },
      append(...kids) { for (const kid of kids) { kid.parent = node; node.children.push(kid); } },
      prepend(kid) { kid.parent = node; node.children.unshift(kid); },
      remove() { if (node.parent) node.parent.children = node.parent.children.filter(c => c !== node); node.parent = null; },
      click() { node.listeners.click?.(); }
    };
    return node;
  };
  const body = make('body');
  const all = node => [node, ...node.children.flatMap(all)];
  return { body, createElement: make, find: cls => all(body).find(n => typeof n.className === 'string' && n.className.split(' ').includes(cls)) };
}

test('banner: Reload only when out of date, Dismiss only before a switch, a dismissed switch stays hidden', () => {
  const doc = fakeDocument();
  let reloads = 0;
  const banner = createUpdateNotice({ doc, reload: () => { reloads++; } });
  const required = updateNoticeOf(parseRulesetCompat(answer({ outcome: 2, generation: '6' })));
  banner.show(required);
  assert.equal(doc.body.children.length, 1);
  const box = doc.find('update-notice');
  assert.equal(box.id, 'nodus-update-notice');
  assert.equal(box.dataset.level, 'required');
  assert.equal(box.attrs.role, 'alert');
  assert.equal(doc.find('update-notice-text').textContent, required.text);
  assert.equal(doc.find('update-notice-details').textContent, required.details);
  assert.equal(doc.find('update-notice-dismiss'), undefined);
  doc.find('update-notice-reload').click();
  assert.equal(reloads, 1);

  const upcoming = updateNoticeOf(parseRulesetCompat(answer({ outcome: 1, nextGeneration: '6', nextHeight: '1720' })));
  banner.show(upcoming);                       // replaces, never stacks
  assert.equal(doc.body.children.length, 1);
  assert.equal(doc.find('update-notice').attrs.role, 'status');
  assert.equal(doc.find('update-notice-reload'), undefined);
  doc.find('update-notice-dismiss').click();
  assert.equal(doc.body.children.length, 0);
  banner.show(upcoming);                       // the same switch again (a reconnect)
  assert.equal(doc.body.children.length, 0);
  banner.show(updateNoticeOf(parseRulesetCompat(answer({ outcome: 1, nextGeneration: '7', nextHeight: '3000' }))));
  assert.equal(doc.body.children.length, 1);   // another switch is shown
  banner.show(null);
  assert.equal(doc.body.children.length, 0);
  banner.show(required);                       // out of date is never hidden by a dismissal
  assert.equal(doc.body.children.length, 1);
});

test('client: rulesetCompat is queued when the module has it; without it the client still unlocks', async () => {
  const mock = createMockNodusModule();
  mock.state.compat = answer({ outcome: 2, generation: '6' });
  const client = createNodusClient({ factory: mock.factory, setInterval: () => 1, clearInterval: () => {} });
  assert.equal(client.compatReadable, false);  // not ready yet
  await client.unlock({ seed: new Uint8Array(32).fill(5), fingerprint: FINGERPRINT });
  assert.equal(client.compatReadable, true);
  assert.equal(parseRulesetCompat(await client.rulesetCompat()).outcome, 2);
  mock.state.compatError = new Error('This Nodus node did not say which transaction rules it runs (an older node, or an unreadable answer; rc=-1). Nothing was built.');
  await assert.rejects(client.rulesetCompat(), /did not say/);
  client.lock();

  const bare = createMockNodusModule();
  delete bare.module.rulesetCompat;
  const old = createNodusClient({ factory: bare.factory, setInterval: () => 1, clearInterval: () => {} });
  await old.unlock({ seed: new Uint8Array(32).fill(5), fingerprint: FINGERPRINT });
  assert.equal(old.state, 'ready');
  assert.equal(old.compatReadable, false);
  await assert.rejects(old.rulesetCompat(), /not available/);
  old.lock();
});

// ── the module's own C rule (parity build) ───────────────────────────────
const PARITY_OUT = process.env.NODUS_SEND_PARITY_OUT;
const skipParity = !PARITY_OUT ? 'set NODUS_SEND_PARITY_OUT (scripts/build-nodus-send-wasm.sh parity)' : false;

test('the module decides with nodus_ruleset_compat and its own max generation', { skip: skipParity }, async () => {
  const path = join(PARITY_OUT, 'send-test-node.mjs');
  assert.ok(existsSync(path), `${path} is missing — run build-nodus-send-wasm.sh parity`);
  const { default: create } = await import(pathToFileURL(path).href);
  const M = await create();
  const json = () => M.ccall('nsw_ri_compat_json', 'string', [], []);
  const keep = (gen, ng, nh, tip) => M.ccall('nsw_test_ri_compat', 'number', ['number', 'number', 'string', 'string'], [gen, ng, nh, tip]);
  assert.equal(json(), '');                                  // nothing read yet
  let max = 0;
  while (M.ccall('nsw_test_pins_tuple', 'string', ['number'], [max + 1])) max++;
  assert.ok(max >= 5, 'the pins header carries generation 5 (HF-7)');
  const read = (...args) => { assert.equal(keep(...args), 0); const r = JSON.parse(json()); assert.equal(r.max, max); return r; };
  assert.equal(read(max + 1, 0, '0', '1000').outcome, 2);   // the network runs a generation this module lacks
  assert.equal(read(max + 1, max + 2, '2000', '1000').outcome, 2);   // 2 is checked first
  assert.deepEqual(read(max, max + 1, '1720', '1000'), { outcome: 1, gen: max, ng: max + 1, nh: '1720', tip: '1000', max });
  assert.equal(read(max, max + 1, '1000', '1000').outcome, 0);       // the switch height is not above the tip
  assert.equal(read(max, max, '1720', '1000').outcome, 0);           // a switch this module carries
  assert.equal(read(max, 0, '0', '1000').outcome, 0);
  assert.equal(keep(1, 0, 'x', '1000'), -1);
  assert.equal(json(), '');                                  // a refused input keeps nothing
});
