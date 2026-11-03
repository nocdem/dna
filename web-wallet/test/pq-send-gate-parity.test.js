// What this proves: the web wallet / Connect gate table and the extension gate
// table are read from ONE shared table (src/pq/send-gates.js), so for every PQ
// chain and network the two surfaces report the same send / history flags,
// except the explicit web override list (XION, Splendor, QTC mainnet send:
// the operator's 2026-11-03 decision "XION, Splendor, QTC ve Ixios'ta gönderme
// eklentide kalır"). The override list is printed so the divergence is visible.
// It also pins the CKB notes to the extension's wording, the "send from the
// extension" notes, that no network carries a balanceNote any more (UI pack
// 2026-11-03) and that the shared table carries no Ixios entry.
// What it needs: node:test only; no build, browser, network or environment
// variable. It reads src/pq/send-gates.js and src/pq/wallet-capabilities.js as text.
// What it leaves behind: nothing (pure functions, no network, no files written).
// How it could falsely pass: the chain list below comes from PQ_NETWORKS, so a
// chain missing there is not compared; Ixios is deliberately excluded because
// its gate stays in the extension file (src/pq/send-gates.js has no Ixios key).
// The Ixios check is a case-insensitive text search of two source files.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { PQ_NETWORKS } from '../src/pq/networks.js';
import * as gates from '../src/pq/send-gates.js';
import { walletCapabilities, walletPageSupported, walletPqNetwork, WEB_SEND_OFF } from '../src/pq/wallet-capabilities.js';
import { extensionCapabilitiesFor, extensionPageSupported, extensionNetworkConfig } from '../extension/src/constants/capabilities.js';
import { CKB_FULL_RECIPIENT_SEND_ENABLED } from '../src/pq/ckb-recipient-policy.js';

const networks = ['mainnet', 'testnet', 'devnet', undefined];
const overridden = (chain, id) => WEB_SEND_OFF.some(([c, n]) => c === chain && n === id);

test('web override list is exactly XION, Splendor, QTC mainnet send (printed)', () => {
  console.log('web send override list (extension sends, web wallet and Connect do not):', JSON.stringify(WEB_SEND_OFF));
  assert.deepEqual([...WEB_SEND_OFF].map(([c, n]) => `${c}:${n}`).sort(), ['qtc:mainnet', 'splendor:mainnet', 'xion:mainnet']);
});

test('walletCapabilities send/history equals extensionCapabilitiesFor except the override list', () => {
  const differences = [];
  for (const chain of Object.keys(PQ_NETWORKS)) for (const id of networks) {
    const web = walletCapabilities(chain, id), ext = extensionCapabilitiesFor(chain, id);
    assert.equal(web.history, ext.history, `${chain} ${id} history`);
    if (overridden(chain, id)) {
      assert.equal(ext.send, true, `${chain} ${id}: an override only exists where the extension sends`);
      assert.equal(web.send, false, `${chain} ${id}: web send is off by the operator's decision`);
      differences.push(`${chain}:${id}`);
    } else assert.equal(web.send, ext.send, `${chain} ${id} send`);
  }
  assert.deepEqual(differences.sort(), ['qtc:mainnet', 'splendor:mainnet', 'xion:mainnet']);
});

test('CKB mainnet send and history are on for the web wallet and Connect', () => {
  assert.equal(walletCapabilities('ckb', 'mainnet').send, true);
  assert.equal(walletCapabilities('ckb', 'mainnet').history, true);
  assert.equal(walletCapabilities('ckb', 'testnet').send, false);
  assert.equal(walletPqNetwork('ckb', PQ_NETWORKS.ckb, 'mainnet').receiveOnly, false);
  assert.equal(walletPqNetwork('ckb', PQ_NETWORKS.ckb, 'testnet').receiveOnly, true);
});

test('page support for send and wallet-activity follows the same table on both surfaces', () => {
  for (const chain of Object.keys(PQ_NETWORKS)) for (const id of networks) {
    assert.equal(walletPageSupported(chain, 'wallet-activity', id), extensionPageSupported(chain, 'wallet-activity', id), `${chain} ${id} wallet-activity`);
    assert.equal(walletPageSupported(chain, 'receive', id), extensionPageSupported(chain, 'receive', id), `${chain} ${id} receive`);
    if (!overridden(chain, id)) assert.equal(walletPageSupported(chain, 'send', id), extensionPageSupported(chain, 'send', id), `${chain} ${id} send page`);
  }
  assert.deepEqual([...gates.PQ_PAGE_HISTORY_CHAINS], ['asentum', 'ckb', 'qtc']);
});

test('CKB notes are the extension wording; XION, Splendor, QTC mainnet say send from the extension', () => {
  const web = walletPqNetwork('ckb', PQ_NETWORKS.ckb, 'mainnet'), ext = extensionNetworkConfig('ckb', PQ_NETWORKS.ckb, 'mainnet');
  assert.equal(web.sendNote, ext.sendNote);
  // UI pack 2026-11-03 (operator "hepsi kalksin"): no note is drawn under any coin, so no network carries a balanceNote.
  assert.equal(web.balanceNote, undefined); assert.equal(ext.balanceNote, undefined);
  for (const [chain, config] of Object.entries(PQ_NETWORKS)) {
    assert.equal(config.balanceNote, undefined, `${chain}: no balanceNote in the registry`);
    for (const id of ['mainnet', 'testnet']) {
      assert.equal(walletPqNetwork(chain, config, id).balanceNote, undefined, `${chain} ${id} web`);
      assert.equal(extensionNetworkConfig(chain, config, id).balanceNote, undefined, `${chain} ${id} extension`);
    }
  }
  assert.equal(typeof CKB_FULL_RECIPIENT_SEND_ENABLED, 'boolean');
  for (const [chain, symbol] of [['xion', 'XION'], ['splendor', 'SPLD'], ['qtc', 'QTC']]) {
    const mainnet = walletPqNetwork(chain, PQ_NETWORKS[chain], 'mainnet');
    assert.equal(mainnet.receiveOnly, true, `${chain} mainnet stays receive only`);
    assert.equal(mainnet.sendNote, `Send ${symbol} from the extension.`);
    const testnet = walletPqNetwork(chain, PQ_NETWORKS[chain], 'testnet');
    assert.equal(testnet.receiveOnly, true);
    assert.equal(testnet.sendNote, PQ_NETWORKS[chain].sendNote, `${chain} testnet keeps today's note`);
  }
});

test('existing web sends are unchanged: Asentum testnet, Soqucoin and Algorand mainnet', () => {
  assert.equal(walletCapabilities('asentum', 'testnet').send, true);
  assert.equal(walletCapabilities('asentum', 'mainnet').send, false);
  assert.equal(walletCapabilities('soqucoin', 'mainnet').send, true);
  assert.equal(walletCapabilities('algorand', 'mainnet').send, true);
  assert.equal(walletCapabilities('algorand', 'testnet').send, false);
  assert.equal(walletPqNetwork('soqucoin', PQ_NETWORKS.soqucoin, 'mainnet').receiveOnly, false);
});

test('the shared table has no Ixios entry and no module of it names Ixios', () => {
  assert.equal(Object.hasOwn(gates.PQ_SEND_GATES, 'ixios'), false);
  for (const file of ['../src/pq/send-gates.js', '../src/pq/wallet-capabilities.js']) assert.doesNotMatch(readFileSync(new URL(file, import.meta.url), 'utf8'), /ixios/i, file);
});
