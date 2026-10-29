import test from 'node:test';
import assert from 'node:assert/strict';
import { setImmediate as nextTurn } from 'node:timers/promises';

// Node 22, no flags; real pinned stream packages, fake window and runtime ports, no disk/storage writes.
class PageMessageEvent extends Event {
  constructor(data, source, origin) { super('message'); this.data = data; this.pageSource = source; this.pageOrigin = origin; }
  get source() { return this.pageSource; }
  get origin() { return this.pageOrigin; }
}
function signal() {
  const listeners = new Set();
  return { listeners, addListener: fn => listeners.add(fn), removeListener: fn => listeners.delete(fn), emit: (...args) => [...listeners].map(fn => fn(...args)) };
}
async function closeConnection(connection) {
  if (!connection) return;
  // ObjectMultiplex.js:35-38,77-80 destroys children on parent completion; finish before destroyStreams removes their pipeline listeners.
  await new Promise(resolve => connection.pageMux.end(resolve));
  await nextTurn();
  assert.equal(connection.pageChannel.destroyed, true);
  assert.equal(connection.caipChannel.destroyed, true);
  connection.destroyStreams();
  connection.pageStream.destroy(); connection.pageMux.destroy();
  await nextTurn();
}
let fixtureId = 0;
async function fixture(t, href = 'https://dapp.example/') {
  const saved = new Map(['window', 'document', 'location', 'MessageEvent', 'chrome', 'browser'].map(key => [key, Object.getOwnPropertyDescriptor(globalThis, key)]));
  const page = new EventTarget();
  page.location = new URL(href);
  page.document = { doctype: { name: 'html' }, documentElement: { nodeName: 'HTML' } };
  page.messages = [];
  page.postMessage = (data, origin) => {
    page.messages.push(structuredClone(data));
    queueMicrotask(() => page.dispatchEvent(new PageMessageEvent(structuredClone(data), page, origin)));
  };
  Object.assign(globalThis, { window: page, document: page.document, location: page.location, MessageEvent: PageMessageEvent });
  const runtime = { id: 'nodus-test-extension', ports: [], onMessage: signal(), lastError: undefined, connect(options) {
    const port = { name: options.name, messages: [], onMessage: signal(), onDisconnect: signal(),
      postMessage(data) { this.messages.push(structuredClone(data)); },
      disconnect() { this.disconnected = true; this.onDisconnect.emit(this); },
    };
    this.ports.push(port); return port;
  } };
  globalThis.chrome = { runtime };
  globalThis.browser = { runtime };
  const { default: browser } = await import('webextension-polyfill');
  browser.runtime = runtime;
  const { contentscript: connection } = await import(`../src/contentscript.js?fixture=${++fixtureId}`);
  let peer;
  t.after(async () => {
    await closeConnection(connection);
    peer?.destroy(); await nextTurn();
    for (const [key, descriptor] of saved) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor); else delete globalThis[key];
    }
  });
  const { WindowPostMessageStream } = await import('@metamask/post-message-stream');
  peer = new WindowPostMessageStream({ name: 'nodus-inpage', target: 'nodus-contentscript' });
  const received = [];
  peer.on('data', data => received.push(data)); peer.on('error', () => {});
  await nextTurn();
  return { page, runtime, peer, received, connection };
}

// Proves real postMessage-to-port framing relays exactly two channels both ways; a fake mux or one-direction-only check could falsely pass.
test('only the renamed EIP-1193 and CAIP channels cross the content bridge', async t => {
  const { runtime, peer, received } = await fixture(t), port = runtime.ports[0];
  assert.equal(port.name, 'nodus-contentscript');
  for (const name of ['nodus-provider', 'nodus-multichain-provider', 'provider', 'publicConfig', 'metamask-provider', 'phishing', 'unknown']) {
    peer.write({ name, data: { id: name, jsonrpc: '2.0', method: 'eth_accounts' } });
    port.onMessage.emit({ name, data: { id: name, jsonrpc: '2.0', result: [] } });
  }
  await nextTurn();
  assert.deepEqual(port.messages.map(message => message.name), ['nodus-provider', 'nodus-multichain-provider']);
  assert.deepEqual(received.map(message => message.name), ['nodus-provider', 'nodus-multichain-provider']);
});

// Proves the post-message stream rejects other origins, sources and targets; a channel-only negative control could miss cross-window injection.
test('foreign postMessage envelopes do not reach the runtime port', async t => {
  const { page, runtime, peer } = await fixture(t), port = runtime.ports[0];
  const envelope = { target: 'nodus-contentscript', data: { name: 'nodus-provider', data: { id: 8, method: 'eth_accounts' } } };
  page.dispatchEvent(new PageMessageEvent(envelope, {}, page.location.origin));
  page.dispatchEvent(new PageMessageEvent(envelope, page, 'https://other.example'));
  page.dispatchEvent(new PageMessageEvent({ ...envelope, target: 'metamask-contentscript' }, page, page.location.origin));
  await nextTurn(); assert.equal(port.messages.length, 0);
  peer.write(envelope.data); await nextTurn(); assert.equal(port.messages.length, 1);
});

// Proves the loaded entry starts without runtime.id and closes its channels before removing listeners; an id-bearing fixture or teardown without completion assertions could falsely pass.
test('the loaded content entry starts unconditionally', async t => {
  const { runtime } = await fixture(t);
  delete runtime.id;
  const { contentscript: second } = await import(`../src/contentscript.js?entry=${++fixtureId}`);
  assert.equal(runtime.ports.length, 2);
  await closeConnection(second);
});

// Proves BFCache/READY rebuild both traffic paths and remove old listeners; port counts alone could conceal a dead relay or duplicate pipelines.
test('BFCache restore and worker READY restore traffic without duplicate ports', async t => {
  const { page, runtime, peer, connection } = await fixture(t);
  const channels = [connection.pageChannel, connection.caipChannel];
  const listenerCounts = () => channels.map(channel => ['close', 'end', 'error'].map(event => channel.listenerCount(event)));
  const initialCounts = listenerCounts();
  const disconnectListeners = [...runtime.ports[0].onDisconnect.listeners];
  assert.ok(disconnectListeners.includes(connection.onDisconnectDestroyStreams));
  const hide = new Event('pagehide'); hide.persisted = true; page.dispatchEvent(hide);
  await nextTurn();
  assert.equal(connection.extensionStream, null);
  assert.deepEqual(listenerCounts(), [[0, 0, 0], [0, 0, 0]]);
  // The reference never removes the port's onMessage listener (extension-port-stream); it disconnects the port.
  assert.equal(runtime.ports[0].disconnected, true);
  const show = new Event('pageshow'); show.persisted = true; page.dispatchEvent(show);
  assert.equal(runtime.ports.length, 2);
  assert.deepEqual(listenerCounts(), initialCounts);
  const responses = runtime.onMessage.emit({ name: 'NODUS_EXTENSION_READY' });
  assert.equal(runtime.ports.length, 2);
  assert.deepEqual(await Promise.all(responses), ['Nodus: handled NODUS_EXTENSION_READY']);
  peer.write({ name: 'nodus-provider', data: { id: 2, method: 'eth_accounts' } });
  await nextTurn(); assert.equal(runtime.ports[1].messages[0].data.id, 2);
  runtime.ports[1].onDisconnect.emit();
  await nextTurn();
  assert.deepEqual(listenerCounts(), [[0, 0, 0], [0, 0, 0]]);
  const readyResponses = runtime.onMessage.emit({ name: 'NODUS_EXTENSION_READY' });
  assert.deepEqual(await Promise.all(readyResponses), ['Nodus: handled NODUS_EXTENSION_READY']);
  assert.equal(runtime.ports.length, 3);
  assert.deepEqual(listenerCounts(), initialCounts);
  runtime.onMessage.emit({ name: 'NODUS_EXTENSION_READY' });
  assert.equal(runtime.ports.length, 3);
  peer.write({ name: 'nodus-multichain-provider', data: { id: 3, method: 'wallet_getSession' } });
  await nextTurn(); assert.equal(runtime.ports[2].messages[0].data.id, 3);
  assert.equal(runtime.ports[1].messages.length, 1);
  assert.deepEqual(runtime.onMessage.emit({ name: 'unrelated' }), [undefined]);
});

// Proves a real Port schedules the one-second reset and replaces both channel pipelines; emitting no Port or checking only port counts could miss callback or listener leaks.
test('a port disconnect waits one second before the reference reset', async t => {
  const { runtime, connection } = await fixture(t);
  const channels = [connection.pageChannel, connection.caipChannel];
  const listenerCounts = () => channels.map(channel => ['close', 'end', 'error'].map(event => channel.listenerCount(event)));
  const initialCounts = listenerCounts();
  t.mock.timers.enable({ apis: ['setTimeout'] });
  runtime.ports[0].onDisconnect.emit(runtime.ports[0]);
  assert.deepEqual(listenerCounts(), [[0, 0, 0], [0, 0, 0]]);
  t.mock.timers.tick(999); assert.equal(runtime.ports.length, 1);
  t.mock.timers.tick(1); assert.equal(runtime.ports.length, 2);
  assert.deepEqual(listenerCounts(), initialCounts);
});

// Proves pipeline errors destroy both ends of the affected channel and reach its callback; a port-count-only lifecycle check would miss this propagation.
test('per-channel pipelines propagate failure to the page channels', async t => {
  const { connection, runtime } = await fixture(t);
  const logs = [];
  t.mock.method(console, 'debug', (...args) => logs.push(args));
  const failure = new Error('Channel fixture failure');
  connection.extensionEip1193Channel.destroy(failure);
  await nextTurn();
  assert.equal(connection.pageChannel.destroyed, true);
  assert.equal(connection.caipChannel.destroyed, false);
  assert.ok(logs.some(([message, error]) => message === 'Nodus: Muxed traffic for channel "nodus-provider" failed.' && error === failure));
  assert.equal(runtime.ports.length, 1);
});

// Proves chainChanged retry uses only data.method and stream failure is notified; a matching provider channel alone would miss an extra name gate.
test('background readiness and stream failure use Nodus notification names', async t => {
  const { runtime, received, page, connection } = await fixture(t), port = runtime.ports[0];
  for (let i = 0; i < 2; i++) port.onMessage.emit({ name: 'nodus-multichain-provider', data: { method: 'nodus_chainChanged', params: {} } });
  await nextTurn();
  assert.equal(received.filter(message => message.data.method === 'NODUS_EXTENSION_CONNECT_CAN_RETRY').length, 1);
  connection.extensionStream.destroy(); await nextTurn();
  assert.equal(page.messages.filter(message => message.data?.data?.method === 'NODUS_STREAM_FAILURE').length, 1);
});

// Proves the pinned URL/domain/document exclusions before opening a port; checking a single domain could hide omitted reference data.
test('provider injection follows the reference exclusions', async t => {
  const { default: shouldInjectProvider, checkURLForProviderInjection, checkDocumentForProviderInjection } = await import('../src/lib/provider-injection.js');
  const saved = new Map(['window', 'document'].map(key => [key, Object.getOwnPropertyDescriptor(globalThis, key)]));
  t.after(() => { for (const [key, descriptor] of saved) {
    if (descriptor) Object.defineProperty(globalThis, key, descriptor); else delete globalThis[key];
  } });
  const doc = { doctype: { name: 'html' }, documentElement: { nodeName: 'HTML' } };
  globalThis.window = { location: new URL('https://dapp.example/'), document: doc };
  globalThis.document = doc;
  assert.equal(shouldInjectProvider.length, 0);
  const check = (url, pageDocument = doc) => {
    window.location = url; window.document = pageDocument; globalThis.document = pageDocument;
    assert.equal(shouldInjectProvider(), checkURLForProviderInjection(url) && checkDocumentForProviderInjection());
    return shouldInjectProvider();
  };
  for (const host of ['execution.consensys.io', 'execution.metamask.io', 'uscourts.gov', 'dropbox.com', 'webbyawards.com', 'adyen.com', 'gravityforms.com', 'harbourair.com', 'ani.gamer.com.tw', 'blueskybooking.com', 'sharefile.com', 'battle.net', 'accounts.google.com', 'accounts.youtube.com', 'appleid.apple.com']) {
    assert.equal(check(new URL(`https://${host}/`)), false, host);
    assert.equal(check(new URL(`https://sub.${host}/`)), false, host);
  }
  for (const path of ['data.xml', 'document.pdf']) assert.equal(check(new URL(`https://dapp.example/${path}`)), false);
  assert.equal(check(new URL('https://cdn.shopify.com/s/javascripts/tricorder/xtld-read-only-frame.html/')), false);
  assert.equal(check(new URL('https://dapp.example/'), { ...doc, doctype: { name: 'svg' } }), false);
  assert.equal(check(new URL('https://dapp.example/'), { ...doc, documentElement: { nodeName: 'svg' } }), false);
  assert.equal(check(new URL('https://notdropbox.com/')), true);
  assert.equal(check(new URL('https://dapp.example/'), { ...doc, doctype: null }), true);
});
