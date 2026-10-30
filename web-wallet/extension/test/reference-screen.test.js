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
  const withoutLockControls = markup => markup.replace(/  <div class="wallet-session">.*?<\/div>\n/u, '')
    .replace(/<button id="lock"[^>]*>.*?<\/button>/u, '')
    .replace(/<p id="portfolio-status"[^>]*>.*?<\/p>/u, '')
    .replace(/<button id="quick-name"[^>]*>.*?<\/button>/u, '')
    .replace(/(<div class="portfolio-heading">)(<p class="portfolio-amount">.*?<\/p>)(<button id="portfolio-hide"[^>]*>.*?<\/button><\/div>)(<p id="portfolio-label"[^>]*>.*?<\/p>)/u, '$1$4$3$2');
  const localSends = '<div class="page-block"><h4 class="activity-subhead">Sent from here</h4><p class="hint">Sends made in this wallet, tracked until final. Once confirmed, a send is listed under Account history where this network\'s history is read. Records stay in this tab unless you choose to save the wallet on this device.</p><div id="activity" class="activity-list" aria-live="polite"></div><p class="activity-empty">No sends recorded here for this network.</p></div>';
  const oldSubtitle = 'Your sends from this wallet and your account history on the selected network.';
  assert.ok(section.includes(localSends)); assert.ok(section.includes(oldSubtitle));
  const reference = section.replace(localSends, '').replace(oldSubtitle, 'Your account history on the selected network.');
  assert.equal(withoutLockControls(WALLET_MARKUP.slice(WALLET_MARKUP.indexOf(body))), withoutLockControls(reference.slice(reference.indexOf(body))));
  assert.doesNotMatch(WALLET_MARKUP, /Sent from here|Sends made in this wallet|No sends recorded here|id="activity"|class="activity-empty"/u);
  assert.doesNotMatch(WALLET_MARKUP, /A WALLET THAT’S YOURS|>Your wallet</u);
  assert.doesNotMatch(WALLET_MARKUP, /id="wallet-heading"[^>]* hidden/u);
  assert.match(WALLET_MARKUP, /<div id="wallet-heading"[^>]*><h2 id="wallet-title"[^>]*>Welcome back<\/h2><button id="wallet-register-name"/u);
  assert.match(WALLET_MARKUP, /id="wallet-register-name"[^>]* hidden>Register your on-chain name<\/button>/u);
  assert.doesNotMatch(WALLET_MARKUP, /class="wallet-mark"|Wallet open in this browser|id="net-status(?:-text)?"/u);
  assert.doesNotMatch(WALLET_MARKUP, /wallet-session|session-timeout/u);
  assert.match(WALLET_MARKUP, /id="portfolio-status"[^>]* hidden/u);
  const lock = WALLET_MARKUP.match(/<button id="lock"[^>]*>(.*?)<\/button>/u);
  assert.ok(lock);
  assert.match(lock[0], /type="button"/u);
  assert.match(lock[0], /aria-label="Lock wallet"/u);
  assert.match(lock[1], /<svg class="app-icon" viewBox="0 0 24 24" aria-hidden="true"/u);
  assert.equal(lock[1].replace(/<[^>]+>/gu, ''), '');
  assert.equal((WALLET_MARKUP.match(/id="lock"/gu) || []).length, 1);
  assert.match(WALLET_MARKUP, /<div class="portfolio-heading"><p class="portfolio-amount">.*?id="portfolio-total".*?<\/p><button id="portfolio-hide"[^>]*>.*?<\/button><button id="lock"[^>]*>.*?<\/button><\/div><p id="portfolio-label"[^>]*>Estimated portfolio value<\/p>/u);
  assert.doesNotMatch(WALLET_MARKUP, /id="quick-name"/u);
});
