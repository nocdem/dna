import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { WALLET_MARKUP } from '../src/ui/wallet-markup.js';

// No flags, network or artifacts. Pins the web-wallet body and the extension's
// greeting slots and approved session/local-send omissions. This cannot prove rendering or event wiring;
// ui-layout.test.js exercises both greetings on the mounted screen in Chromium.
test('extension keeps the web wallet body apart from the approved polish and local-send removal', async () => {
  const source = await readFile(new URL('../../index.html', import.meta.url), 'utf8');
  const section = source.slice(source.indexOf('<section class="card wallet-card"'), source.indexOf('\n\n<details class="danger-zone"'));
  const body = '\n<p id="wallet-boot-status"';
  assert.ok(WALLET_MARKUP.includes(body)); assert.ok(section.includes(body));
  const withoutSession = markup => markup.replace(/<div class="wallet-session">.*?<\/div>\n/u, '');
  const localSends = '<div class="page-block"><h4 class="activity-subhead">Sent from here</h4><p class="hint">Sends made in this wallet, tracked until final. Once confirmed, a send is listed under Account history where this network\'s history is read. Records stay in this tab unless you choose to save the wallet on this device.</p><div id="activity" class="activity-list" aria-live="polite"></div><p class="activity-empty">No sends recorded here for this network.</p></div>';
  const oldSubtitle = 'Your sends from this wallet and your account history on the selected network.';
  assert.ok(section.includes(localSends)); assert.ok(section.includes(oldSubtitle));
  const reference = section.replace(localSends, '').replace(oldSubtitle, 'Your account history on the selected network.');
  assert.equal(withoutSession(WALLET_MARKUP.slice(WALLET_MARKUP.indexOf(body))), withoutSession(reference.slice(reference.indexOf(body))));
  assert.doesNotMatch(WALLET_MARKUP, /Sent from here|Sends made in this wallet|No sends recorded here|id="activity"|class="activity-empty"/u);
  assert.doesNotMatch(WALLET_MARKUP, /A WALLET THAT’S YOURS|>Your wallet</u);
  assert.match(WALLET_MARKUP, /id="wallet-heading"[^>]* hidden/u);
  assert.match(WALLET_MARKUP, /<h2 id="wallet-title"[^>]*><\/h2>/u);
  assert.match(WALLET_MARKUP, /id="wallet-register-name"[^>]* hidden>Register your on-chain name<\/button>/u);
  assert.doesNotMatch(WALLET_MARKUP, /class="wallet-mark"|Wallet open in this browser|id="net-status(?:-text)?"/u);
  assert.match(WALLET_MARKUP, /id="session-timeout"/u);
  assert.match(WALLET_MARKUP, /id="lock"[^>]*>Lock wallet<\/button>/u);
});
