import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { WALLET_MARKUP } from '../src/ui/wallet-markup.js';

// No flags, network or artifacts. Pins the web-wallet body and the extension's
// greeting slots. This cannot prove rendering or event wiring;
// ui-layout.test.js exercises both greetings on the mounted screen in Chromium.
test('extension replaces only the web wallet card heading with greeting slots', async () => {
  const source = await readFile(new URL('../../index.html', import.meta.url), 'utf8');
  const section = source.slice(source.indexOf('<section class="card wallet-card"'), source.indexOf('\n\n<details class="danger-zone"'));
  const body = '\n<p id="wallet-boot-status"';
  assert.ok(WALLET_MARKUP.includes(body)); assert.ok(section.includes(body));
  assert.equal(WALLET_MARKUP.slice(WALLET_MARKUP.indexOf(body)), section.slice(section.indexOf(body)));
  assert.doesNotMatch(WALLET_MARKUP, /A WALLET THAT’S YOURS|>Your wallet</u);
  assert.match(WALLET_MARKUP, /id="wallet-heading"[^>]* hidden/u);
  assert.match(WALLET_MARKUP, /<h2 id="wallet-title"[^>]*><\/h2>/u);
  assert.match(WALLET_MARKUP, /id="wallet-register-name"[^>]* hidden>Register your on-chain name<\/button>/u);
});
