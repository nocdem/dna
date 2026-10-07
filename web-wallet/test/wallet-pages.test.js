// Wallet pages (0.1.75; operator 2026-10-08: "everything was piled onto the
// wallet page" — the wallet page shows only the wallet, everything else is a
// separate page). src/app.js shows the open wallet's own view (#wallet-home:
// Portfolio and Send / Receive) OR one page, named by the URL hash.
//
// What it proves, on both sites (index.html, connect-site/index.html):
// #wallet-home holds Portfolio and Send / Receive and none of the pages'
// panels; Earn, Shared vaults, Smart contracts, Activity, Address book,
// Device & settings and Logs are each one `.wallet-page` wrapper, hidden in
// the markup, named by data-page, holding a "Back to wallet" control and
// exactly one panel whose title (aria-labelledby) can take focus; every
// navigation entry for a section other than Portfolio and Send / Receive
// opens its page; no page name is also an element id (a hash would then
// scroll to that element); the session log sits on the Logs page only and
// Device & settings links to it; a hash naming an element on a page (the
// vault card's "Open vault" → #vault-panel, src/vaults/ui.js) opens that
// page. In src/app.js: the browser's history is
// reached as window.history (`history` in that file is the account-history
// list), the pagehide lock keeps the page hash for a reload and every other
// lock clears it, and the unlock routes from the hash. In
// src/connect-main.js: More → Address book, Device & settings and Logs open
// their pages.
//
// What it requires: nothing beyond the sources (no build, no browser).
// What it leaves behind: nothing.
//
// How it can lie: it reads the source TEXT, it does not run the page.
// Whether a page is shown, focused and scrolled as described is checked by
// the browser tests (test/browser-smoke.js, test/connect-smoke.js), not here.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = path => readFileSync(new URL(path, import.meta.url), 'utf8');
const app = read('../src/app.js');
const connectMain = read('../src/connect-main.js');
const SITES = [['index.html', read('../index.html')], ['connect-site/index.html', read('../connect-site/index.html')]];
// page name → the panel it holds
const PAGES = {
  earn: 'stake-panel', vaults: 'vault-panel', contracts: 'evm-panel', 'wallet-activity': 'activity-panel',
  'address-book': 'address-book-panel', settings: 'device-panel', logs: 'logs-panel'
};

// The element (outer HTML) whose opening tag starts at `start`, by counting
// nested tags of the same name.
function element(html, start) {
  const name = html.slice(start).match(/^<([a-z][a-z0-9]*)/)[1];
  const tags = new RegExp(`<(/?)${name}\\b[^>]*>`, 'g');
  tags.lastIndex = start;
  let depth = 0, match;
  while ((match = tags.exec(html))) {
    depth += match[1] ? -1 : 1;
    if (depth === 0) return html.slice(start, tags.lastIndex);
  }
  throw new Error(`unclosed <${name}> at ${start}`);
}
const byId = (html, id) => {
  const at = html.search(new RegExp(`<[a-z][a-z0-9]*\\s(?:[^>]*\\s)?id="${id}"[^>]*>`));
  return at < 0 ? null : element(html, at);
};
const openingTag = outer => outer.match(/^<[^>]*>/)[0];

for (const [site, html] of SITES) {
  test(`${site}: the wallet view holds Portfolio and Send / Receive only`, () => {
    const home = byId(html, 'wallet-home');
    assert.ok(home, '#wallet-home exists');
    for (const id of ['assets-panel', 'send-form', 'portfolio-total']) assert.ok(home.includes(`id="${id}"`), `${id} is in the wallet view`);
    for (const panel of Object.values(PAGES)) assert.ok(!home.includes(`id="${panel}"`), `${panel} is not in the wallet view`);
    assert.ok(!home.includes('class="wallet-page"'), 'no page inside the wallet view');
  });

  test(`${site}: every other section is a hidden page with a Back control and one titled panel`, () => {
    const pages = html.match(/class="wallet-page"/g) || [];
    assert.equal(pages.length, Object.keys(PAGES).length, 'one wrapper per page, no other');
    for (const [name, panel] of Object.entries(PAGES)) {
      const page = byId(html, `page-${name}`);
      assert.ok(page, `#page-${name} exists`);
      const tag = openingTag(page);
      assert.ok(/^<div\b/.test(tag) && tag.includes('class="wallet-page"') && tag.includes(`data-page="${name}"`) && /\shidden(?=[\s>])/.test(tag), `#page-${name} is a hidden .wallet-page named ${name}`);
      assert.ok(/^<div[^>]*>\s*<button type="button" class="secondary small page-back"><span aria-hidden="true">←<\/span> Back to wallet<\/button>/.test(page), `#page-${name} opens with its Back control`);
      assert.equal((page.match(/class="dashboard-panel\b/g) || []).length, 1, `#page-${name} holds one panel`);
      const section = byId(page, panel);
      assert.ok(section && section.includes('class="dashboard-panel'), `#page-${name} holds #${panel}`);
      const title = openingTag(section).match(/aria-labelledby="([^"]+)"/)?.[1];
      assert.ok(title, `#${panel} names its title`);
      assert.ok(/\stabindex="-1"/.test(openingTag(byId(section, title))), `#${title} can take focus`);
    }
  });

  test(`${site}: the navigation opens the pages; page names are not element ids`, () => {
    const nav = byId(html, 'wallet-home').match(/<nav class="wallet-navigation"[^>]*>([\s\S]*?)<\/nav>/)[1];
    const hrefs = [...nav.matchAll(/href="#([^"]+)"/g)].map(match => match[1]);
    assert.deepEqual(hrefs, ['assets-panel', 'send-form', 'earn', 'vaults', 'contracts', 'wallet-activity', 'address-book', 'settings']);
    for (const name of Object.keys(PAGES)) assert.ok(!new RegExp(`\\sid="${name}"`).test(html), `no element has the id ${name}`);
    for (const [id, name] of [['nav-earn', 'earn'], ['nav-vaults', 'vaults'], ['nav-evm', 'contracts']]) {
      const link = openingTag(byId(html, id));
      assert.ok(link.includes(`href="#${name}"`) && /\shidden(?=[\s>])/.test(link), `#${id} opens #${name} and is hidden until available`);
    }
  });

  test(`${site}: Logs is its own page, linked from Device & settings`, () => {
    const logs = byId(html, 'page-logs');
    assert.ok(byId(logs, 'session-logs'), '#session-logs is on the Logs page');
    assert.equal((html.match(/id="session-logs"/g) || []).length, 1, 'and nowhere else');
    assert.ok(!byId(html, 'device-panel').includes('id="session-logs"'), 'not in Device & settings');
    assert.ok(/<a href="#logs">Logs<\/a>/.test(byId(html, 'device-panel')), 'Device & settings links to the Logs page');
  });
}

test('src/app.js reaches the browser history as window.history (its own `history` is the account history)', () => {
  assert.ok(/^const history = \[\];/m.test(app), 'the shadowing list still exists (this test guards it)');
  assert.deepEqual(app.match(/(?<!window\.)\bhistory\.(pushState|replaceState|back|forward|go|state|scrollRestoration)\b/g), null);
  assert.ok(app.includes('window.history.pushState('), 'pages are pushed as history entries');
  assert.ok(/addEventListener\('hashchange', \(\) => routeFromHash\(\)\)/.test(app), 'the hash routes');
});

test('src/app.js: the pagehide lock keeps the page hash, every other lock clears it; the unlock routes', () => {
  assert.ok(/^function lock\(event\) \{/m.test(app), 'lock takes the listener event');
  assert.ok(app.includes("resetWalletPages({ keepHash: event?.type === 'pagehide' });"), 'only pagehide keeps the hash');
  assert.ok(app.includes("window.addEventListener('pagehide', lock);"), 'pagehide is a lock');
  const focusOpen = app.slice(app.indexOf('function focusOpenWallet('));
  assert.ok(/^function focusOpenWallet\([^)]*\) \{[\s\S]*?routeFromHash\(\);\n\}/.test(focusOpen), 'opening the wallet routes from the hash');
});

test('an in-page link to an element on a page opens that page (Messages\' "Open vault" → #vault-panel)', () => {
  assert.ok(read('../src/vaults/ui.js').includes("link.href = '#vault-panel';"), 'the vault card links to #vault-panel');
  for (const [site, html] of SITES) assert.ok(byId(byId(html, 'page-vaults'), 'vault-panel'), `${site}: #vault-panel is on the Shared vaults page`);
  assert.ok(app.includes("return document.getElementById(name)?.closest('.wallet-page')?.dataset.page || null;"), 'hashPage resolves an element id to the page holding it');
});

test('src/connect-main.js: More opens the address book, Device & settings and Logs pages', () => {
  for (const [row, name] of [['more-address-book', 'address-book'], ['more-device', 'settings'], ['more-logs', 'logs']]) {
    assert.ok(connectMain.includes(`$('${row}').onclick = () => openWalletPage('${name}');`), `${row} opens #${name}`);
  }
  assert.ok(!/scrollIntoView/.test(connectMain.slice(connectMain.indexOf('// More.'), connectMain.indexOf('// Status line'))), 'no More row scrolls into the wallet view any more');
});
