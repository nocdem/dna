// What this proves: the web wallet / Connect gate table and the extension gate
// table are read from ONE shared table (src/pq/send-gates.js), so for every PQ
// chain and network the two surfaces report the same send / history flags,
// except the explicit web override list (XION, Splendor, QTC mainnet send:
// the operator's 2026-11-03 decision "XION, Splendor, QTC ve Ixios'ta gönderme
// eklentide kalır"). The override list is printed so the divergence is visible.
// It also pins the CKB notes to the extension's wording, the "send from the
// extension" notes, that no network carries a balanceNote any more (UI pack
// 2026-11-03) and, since 2026-11-14 (operator, decisions/2026-09-23-ixios-send-
// mainnet-first.md "Değişiklik 3": Ixios sends on the web wallet and Connect like
// the extension), that Ixios is in the shared table for every listed network
// (mainnet, test network), off for any unlisted id, with the same flags and the
// same notes on the web wallet / Connect and the extension.
// What it needs: node:test only; no build, browser, network or environment
// variable.
// What it leaves behind: nothing (pure functions, no network, no files written).
// How it could falsely pass: the PQ chain list below comes from PQ_NETWORKS, so a
// chain missing there is not compared (Ixios is compared by its own tests, over
// IXIOS_NETWORKS plus 'devnet' and undefined); a note changed identically on both
// surfaces still passes the parity checks, the literal note strings pin the wording.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { PQ_NETWORKS } from '../src/pq/networks.js';
import * as gates from '../src/pq/send-gates.js';
import { walletCapabilities, walletPageSupported, walletPqNetwork, walletIxiosNetwork, WEB_SEND_OFF } from '../src/pq/wallet-capabilities.js';
import { IXIOS_NETWORK, IXIOS_NETWORKS } from '../src/pq/ixios/network.js';
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

test('Ixios: the shared table lists exactly the networks of IXIOS_NETWORKS, send and history on; any other id gets neither', () => {
  assert.deepEqual(Object.keys(gates.PQ_SEND_GATES.ixios.networks).sort(), Object.keys(IXIOS_NETWORKS).sort());
  for (const id of Object.keys(IXIOS_NETWORKS)) {
    assert.deepEqual({ ...gates.pqSendGate('ixios', id) }, { send: true, history: true }, id);
    assert.equal(walletCapabilities('ixios', id).send, true, `web ${id} send`);
    assert.equal(walletCapabilities('ixios', id).history, true, `web ${id} history`);
    assert.equal(walletPageSupported('ixios', 'send', id), true, `web ${id} send page`);
    assert.equal(walletPageSupported('ixios', 'wallet-activity', id), true, `web ${id} activity page`);
  }
  for (const id of ['devnet', 'constructor', '__proto__', '', undefined, 1]) {
    assert.deepEqual({ ...gates.pqSendGate('ixios', id) }, { send: false, history: false }, String(id));
    assert.equal(walletCapabilities('ixios', id).send, false, `web ${String(id)} send`);
    assert.equal(walletCapabilities('ixios', id).history, false, `web ${String(id)} history`);
    assert.equal(walletPageSupported('ixios', 'send', id), false, `web ${String(id)} send page`);
  }
  // Ixios is not in the web override list: the web wallet sends wherever the extension does.
  assert.equal(WEB_SEND_OFF.some(([chain]) => chain === 'ixios'), false);
});

test('Ixios: web wallet / Connect and extension report the same flags and pages for every network id', () => {
  for (const id of [...Object.keys(IXIOS_NETWORKS), 'devnet', undefined]) {
    const web = walletCapabilities('ixios', id), ext = extensionCapabilitiesFor('ixios', id);
    assert.deepEqual({ send: web.send, history: web.history, receive: web.receive, balance: web.balance }, { send: ext.send, history: ext.history, receive: ext.receive, balance: ext.balance }, String(id));
    for (const page of ['send', 'wallet-activity', 'receive']) assert.equal(walletPageSupported('ixios', page, id), extensionPageSupported('ixios', page, id), `${String(id)} ${page}`);
  }
});

test('Ixios: the web network config carries the extension note and receiveOnly for every network id; the "from the extension" note is gone', () => {
  const noteOf = id => extensionNetworkConfig('ixios', IXIOS_NETWORK, id);
  for (const id of [...Object.keys(IXIOS_NETWORKS), 'devnet', undefined]) {
    const web = walletIxiosNetwork(IXIOS_NETWORK, id), ext = noteOf(id);
    assert.equal(web.sendNote, ext.sendNote, `${String(id)} note`);
    assert.equal(web.receiveOnly, ext.receiveOnly, `${String(id)} receiveOnly`);
    assert.notEqual(web.sendNote, 'Send IXIOS from the extension.');
  }
  assert.equal(walletIxiosNetwork(IXIOS_NETWORK, 'mainnet').receiveOnly, false);
  assert.equal(walletIxiosNetwork(IXIOS_NETWORK, 'testnet').receiveOnly, false);
  assert.equal(walletIxiosNetwork(IXIOS_NETWORK, 'devnet').receiveOnly, true);
  // Literal wording, so a change made to both surfaces cannot satisfy the equality above.
  assert.equal(walletIxiosNetwork(IXIOS_NETWORK, 'mainnet').sendNote, 'Native IXIOS only, 1,000 gas and an explicit gas-price cap. Fresh identity/fee checks must pass; live RPC availability is not guaranteed. No contracts, tokens or automatic replacement.');
  assert.match(walletIxiosNetwork(IXIOS_NETWORK, 'testnet').sendNote, /^Ixios test network: test IXIOS only\. Native IXIOS only, 1,000 gas/);
  assert.equal(walletIxiosNetwork(IXIOS_NETWORK, 'devnet').sendNote, 'IXIOS sends are available only on the mainnet code candidate.');
  // The shared source names Ixios only where the gate and its note live (the table and the web note function).
  assert.match(readFileSync(new URL('../src/pq/send-gates.js', import.meta.url), 'utf8'), /ixios: Object\.freeze/);
});
