import test from 'node:test';
import assert from 'node:assert/strict';
import { NET_STATUS_TEXT, netLevelFor, netStatusView } from '../src/net-status.js';

test('every NODUS client state maps to one network level; only ready is connected', () => {
  // src/nodus/client.js STATES
  assert.equal(netLevelFor('ready'), 'connected');
  for (const state of ['identifying', 'identified', 'connecting']) assert.equal(netLevelFor(state), 'connecting', state);
  for (const state of ['idle', 'error', 'locked']) assert.equal(netLevelFor(state), 'offline', state);
  // a state this mapping does not know is never shown as connected
  for (const state of [undefined, null, '', 'READY', 'ready ', 'opened']) assert.equal(netLevelFor(state), 'offline', String(state));
});

test('each level shows its own dot level and plain-language text', () => {
  assert.deepEqual(netStatusView('connected'), { level: 'connected', text: 'Connected to the Nodus network' });
  assert.deepEqual(netStatusView('connecting'), { level: 'connecting', text: 'Connecting to the Nodus network…' });
  assert.deepEqual(netStatusView('offline'), { level: 'offline', text: 'Not connected to the Nodus network. Lock and reopen your wallet to retry.' });
  // no module in this build: nothing is shown
  assert.equal(netStatusView('off'), null);
  // an unknown level is shown as not connected, never as connected
  for (const level of [undefined, 'ready', 'toString', '__proto__']) assert.deepEqual(netStatusView(level), { level: 'offline', text: NET_STATUS_TEXT.offline }, String(level));
});

test('client states end in the expected bar text', () => {
  assert.equal(netStatusView(netLevelFor('ready')).text, NET_STATUS_TEXT.connected);
  assert.equal(netStatusView(netLevelFor('connecting')).text, NET_STATUS_TEXT.connecting);
  assert.equal(netStatusView(netLevelFor('error')).text, NET_STATUS_TEXT.offline);
  // user-facing text never names the transport
  for (const text of Object.values(NET_STATUS_TEXT)) assert.doesNotMatch(text, /DHT|WebSocket|node/i);
  assert.ok(Object.isFrozen(NET_STATUS_TEXT));
});
