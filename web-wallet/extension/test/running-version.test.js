import test from 'node:test';
import assert from 'node:assert/strict';

// No flags, network or artifacts. Proves the label text comes from the running
// manifest version, is added once, and is skipped without a version. It cannot
// prove placement or looks; the browser screenshot of the built package does.
import { showRunningVersion } from '../src/ui/running-version.js';

function fakeDocument() {
  const appended = [];
  return {
    appended,
    createElement: tag => ({ tag, className: '', textContent: '' }),
    querySelector: selector => appended.find(node => selector === '.' + node.className) || null,
    body: { append: node => appended.push(node) },
  };
}

test('the running version is shown once, from the manifest', () => {
  const document = fakeDocument();
  const runtime = { getManifest: () => ({ version: '0.1.163' }) };
  showRunningVersion(document, runtime);
  showRunningVersion(document, runtime);
  assert.equal(document.appended.length, 1);
  assert.equal(document.appended[0].tag, 'small');
  assert.equal(document.appended[0].className, 'extension-version');
  assert.equal(document.appended[0].textContent, 'v0.1.163');
});

test('no label without a manifest version', () => {
  const document = fakeDocument();
  showRunningVersion(document, { getManifest: () => ({}) });
  showRunningVersion(document, undefined);
  assert.equal(document.appended.length, 0);
});
