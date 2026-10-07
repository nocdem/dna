// Nodus Connect offers the wallet's smart-contracts panel (src/evm/ui.js)
// the way it offers the shared vaults: mounted on Connect's own markup and
// registered as a wallet extension (src/wallet-extensions.js) BEFORE
// src/app.js loads, so it hears the first unlock.
//
// What it proves: src/connect-main.js imports src/evm/ui.js, mounts the panel
// on #evm-panel / #evm-root and registers smartContractExtension before it
// imports src/app.js (as src/main.js does on the wallet page);
// connect-site/index.html carries #evm-panel, #evm-root and the #nav-evm link,
// the panel and the link hidden in the markup (src/evm/ui.js showPanel only
// un-hides them once the node reports the EVM generation), and the #chain
// select showPanel reads; since 0.1.75 the panel is a page of its own
// (#page-contracts, opened by #nav-evm's #contracts link) and not part of the
// wallet view (#wallet-home), and Nodus Connect's More menu has a Smart
// contracts row that follows #nav-evm and opens that page; the two pages'
// Content-Security-Policy is the same string, so the EVM path loads under the
// same policy on both sites.
//
// What it requires: nothing beyond the sources (no build, no browser, no
// node, no send.wasm). What it leaves behind: nothing.
//
// How it can lie: it reads the source TEXT, it does not run the page. A
// call that is present but never reached (e.g. an earlier throw in the same
// try block), a panel id renamed in src/evm/ui.js, or CSS that hides the
// panel would all pass here. Whether the panel is drawn, and where in the
// Wallet tab, is not checked (no browser test opens the connected Wallet
// tab with an EVM-capable node).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = path => readFileSync(new URL(path, import.meta.url), 'utf8');
const connectMain = read('../src/connect-main.js');
const walletMain = read('../src/main.js');
const connectHtml = read('../connect-site/index.html');
const walletHtml = read('../index.html');

// The opening tag of the element with this id, or null.
function tagWithId(html, id) {
  const match = html.match(new RegExp(`<[a-z]+[^>]*\\sid="${id}"[^>]*>`));
  return match ? match[0] : null;
}
const csp = html => html.match(/http-equiv="Content-Security-Policy" content="([^"]*)"/)?.[1];

for (const [site, source] of [['Nodus Connect (src/connect-main.js)', connectMain], ['wallet (src/main.js)', walletMain]]) {
  test(`${site} mounts and registers the smart-contracts extension before src/app.js loads`, () => {
    const imported = source.indexOf("import('./evm/ui.js')");
    const mounted = source.search(/mountSmartContracts\(\{\s*panelNode:[^}]*'evm-panel'[^}]*rootNode:[^}]*'evm-root'[^}]*\}\)/);
    const registered = source.indexOf('registerExtension(smartContractExtension)');
    const app = source.indexOf("await import('./app.js')");
    assert.ok(imported >= 0, 'src/evm/ui.js is imported');
    assert.ok(/\{\s*mountSmartContracts,\s*smartContractExtension\s*\}/.test(source), 'mountSmartContracts and smartContractExtension are taken from it');
    assert.ok(mounted >= 0, 'the panel is mounted on #evm-panel / #evm-root');
    assert.ok(registered >= 0, 'smartContractExtension is registered');
    assert.ok(app >= 0, 'src/app.js is imported');
    assert.ok(imported < app && mounted < app && registered < app, 'all before src/app.js loads');
  });
}

for (const [site, html] of [['connect-site/index.html', connectHtml], ['index.html', walletHtml]]) {
  test(`${site} carries the smart-contracts panel and its link, hidden until the EVM generation is reported`, () => {
    const panel = tagWithId(html, 'evm-panel');
    assert.ok(panel, '#evm-panel exists');
    assert.ok(/^<section\b/.test(panel) && /\shidden(?=[\s>])/.test(panel), '#evm-panel is a hidden section');
    assert.ok(tagWithId(html, 'evm-root'), '#evm-root exists');
    const nav = tagWithId(html, 'nav-evm');
    assert.ok(nav, '#nav-evm exists');
    assert.ok(/href="#contracts"/.test(nav) && /\shidden(?=[\s>])/.test(nav), '#nav-evm opens the Smart contracts page (#contracts) and is hidden');
    assert.ok(tagWithId(html, 'chain'), '#chain (read by showPanel) exists');
    // The panel is the Smart contracts page of its own (0.1.75), not a
    // section of the wallet view.
    const page = html.match(/<div id="page-contracts" class="wallet-page" data-page="contracts" hidden>([\s\S]*?)<\/section><\/div>/);
    assert.ok(page, '#page-contracts is a hidden wallet page');
    assert.ok(page[1].includes('id="evm-panel"') && page[1].includes('class="secondary small page-back"'), 'it holds #evm-panel and a Back control');
    const home = html.match(/<div id="wallet-home">([\s\S]*?)<div id="page-earn"/);
    assert.ok(home && !home[1].includes('id="evm-panel"'), '#evm-panel is not in the wallet view');
  });
}

test('Nodus Connect lists Smart contracts in More only while the wallet\'s link is shown, and opens the page', () => {
  const item = tagWithId(connectHtml, 'more-contracts-item');
  assert.ok(item && /\shidden(?=[\s>])/.test(item), '#more-contracts-item exists, hidden in the markup');
  assert.ok(tagWithId(connectHtml, 'more-contracts'), '#more-contracts exists');
  assert.ok(/\$\('more-contracts-item'\)\.hidden = \$\('nav-evm'\)\.hidden/.test(connectMain), 'the row follows #nav-evm');
  assert.ok(/observe\(\$\('nav-evm'\), \{ attributes: true, attributeFilter: \['hidden'\] \}\)/.test(connectMain), 'and is kept in step with it');
  assert.ok(/\$\('more-contracts'\)\.onclick = \(\) => \{ if \(!\$\('nav-evm'\)\.hidden\) openWalletPage\('contracts'\); \};/.test(connectMain), 'the row opens the contracts page');
});

test('the wallet and Nodus Connect pages have the same Content-Security-Policy', () => {
  assert.ok(csp(walletHtml), 'wallet CSP found');
  assert.equal(csp(connectHtml), csp(walletHtml));
});
