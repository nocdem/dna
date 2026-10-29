import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { WALLET_MARKUP } from '../src/ui/wallet-markup.js';

// No flags, network or artifacts. Pins the actual web-wallet section, including
// controls whose trusted methods are still pending. This cannot prove rendering
// or event wiring; ui-layout.test.js exercises the mounted screen in Chromium.
test('extension carries the web wallet section verbatim', async () => {
  const source = await readFile(new URL('../../index.html', import.meta.url), 'utf8');
  const section = source.slice(source.indexOf('<section class="card wallet-card"'), source.indexOf('\n\n<details class="danger-zone"'));
  assert.equal(WALLET_MARKUP, section);
});
