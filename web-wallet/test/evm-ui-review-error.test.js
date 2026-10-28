// What it proves: the Smart contracts Review actions (deposit, withdrawal,
// deployment and each writable function) carry distinct keys through
// prepareAndShow to act. A failure in the current wallet generation keeps
// the existing top status and records an inline error for that key. The
// matching Review button renders the message as text in an adjacent alert;
// another Review clears it before rendering, and wallet reset clears it.
// The Collect action keeps its existing prepareAndShow path.
//
// Requirements: Node's test runner and the source files only; no DOM,
// browser, build, network or wallet. Compile flags: none. Environment
// variables: none. Leaves behind: nothing. There are no conditional skips.
//
// How it can falsely pass: these assertions inspect source TEXT without
// executing the panel. Matching code could be unreachable or duplicated in
// a comment; other styles could hide the alert. Actual placement, scrolling,
// asynchronous interaction and screen-reader announcements need a browser
// check and are not proved here.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = path => readFileSync(new URL(path, import.meta.url), 'utf8');
const ui = read('../src/evm/ui.js');
const css = read('../src/style.css');

function section(start, end) {
  const from = ui.indexOf(start), to = ui.indexOf(end, from + start.length);
  assert.ok(from >= 0 && to > from, `source section exists: ${start}`);
  return ui.slice(from, to);
}

test('Review errors survive rendering, clear on the next Review and reset with the wallet', () => {
  assert.match(ui, /let reviewError = null;/);
  assert.match(section('function reset()', 'function start('), /reviewError = null;/);
  const act = section('async function act(', 'async function refreshBalance(');
  assert.match(act, /async function act\(work, reviewKey = null\)/);
  assert.match(act, /if \(busy\) return;\s*if \(reviewKey !== null\) reviewError = null;\s*busy = true; status = ''; render\(\);/);
  assert.match(act, /catch \(error\) \{\s*if \(gen === generation\) \{\s*status = error\?\.message \|\| 'Something went wrong\.';\s*if \(reviewKey !== null\) reviewError = \{ key: reviewKey, message: status \};/);
  assert.match(act, /finally \{ if \(gen === generation\) \{ busy = false; render\(\); \} \}/);
});

test('only the matching Review button gets the adjacent text alert', () => {
  const action = section('function reviewAction(', 'async function prepareAndShow(');
  assert.match(action, /const button = btn\(label, \(\) => void prepareAndShow\(prepare, title, extra, key\), ''\);/);
  assert.match(action, /if \(reviewError\?\.key !== key\) return \[button\];/);
  assert.match(action, /const error = el\('p', \{ className: 'notice evm-error evm-review-error', text: reviewError\.message \}\);/);
  assert.match(action, /error\.setAttribute\('role', 'alert'\);/);
  assert.match(action, /return \[button, error\];/);
  assert.match(section('function el(', 'function btn('), /node\.textContent = text;/);
  assert.doesNotMatch(action, /innerHTML/);
});

test('all four Review call sites use distinct action keys in their own forms', () => {
  const bridge = section('function renderBridge()', 'function renderTickets()');
  assert.match(bridge, /\.\.\.reviewAction\('deposit', 'Review', \(\) => account\.deposit\(/);
  assert.match(bridge, /\.\.\.reviewAction\('withdraw', 'Review', \(\) => \{/);
  assert.match(section('function renderDeploy()', 'function renderContract()'), /\.\.\.reviewAction\(deployDraft, 'Review deployment', \(\) => Contract\.prepareDeploy\(/);
  assert.match(section('function renderContract()', 'const STATE_TEXT'), /form\.append\(\.\.\.reviewAction\(fn, 'Review', \(\) => contract\.prepareSend\(/);
  assert.equal([...ui.matchAll(/\.\.\.reviewAction\(/g)].length, 4, 'every Review action uses the shared inline alert path');
  assert.doesNotMatch(ui, /btn\('Review(?: deployment)?',/);
});

test('preparation forwards the key while retaining the existing success and stale-generation paths', () => {
  const prepare = section('async function prepareAndShow(', 'async function lookTicket(');
  assert.match(prepare, /async function prepareAndShow\(prepare, title, extra, reviewKey = null\)/);
  assert.match(prepare, /await act\(async gen => \{\s*const view = await prepare\(\);\s*if \(gen !== generation\) \{ view\.cancel\(\); return; \}\s*showReview\(view, title, \(sent, warning\) => track\(sent, title, extra, warning\)\);\s*\}, reviewKey\);/);
  assert.match(section('function renderTickets()', 'function argField('), /btn\('Collect', \(\) => void prepareAndShow\(\(\) => account\.redeem\(id, t\.dest\), 'Collect a withdrawal ticket'\)\)/);
});

test('the top status message and error logging remain in place', () => {
  assert.match(section('async function act(', 'async function refreshBalance('), /sessionLog\.log\('evm', status, \{ error: true \}\);/);
  const render = section('function render()', 'export function mountSmartContracts(');
  assert.match(render, /const line = el\('p', \{ className: 'hint evm-status', text: status \}\);/);
  assert.match(render, /line\.setAttribute\('role', 'status'\); line\.setAttribute\('aria-live', 'polite'\);/);
  assert.match(render, /const items = \[[^\n]*, line, renderAccount\(\)\];/);
});

test('inline errors wrap long messages and occupy a row beside deployment actions', () => {
  assert.match(css, /\.evm-review-error\s*\{[^}]*overflow-wrap:\s*anywhere;/);
  assert.match(css, /\.evm-actions > \.evm-review-error\s*\{[^}]*flex-basis:\s*100%;/);
});
