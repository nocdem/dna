import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { logWebSocketsFor, setDebugLogSink } from '../../src/debug-log.js';

// The socket wrapper of the debug logger is installed ONCE per process (it extends the global WebSocket that exists at
// that moment), so these tests live in their own file and share one fake native WebSocket and one installation made at
// file level. Environment: Node >=22.14, a fake native WebSocket (no network, no sockets), no flags, nothing left on disk.
// Every socket made below is a socket of the wrapper (globalThis.WebSocket after the installation).
const sent = [], made = [];
const NativeFake = class {
  constructor(url) { this.url = url; this.listeners = {}; made.push(this); }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  send(data) { sent.push(data); return 'native-result'; }
};
const savedWebSocket = globalThis.WebSocket;
globalThis.WebSocket = NativeFake;
// Two configured endpoints, as the send module registers them: the URL it opens. One on a non-default port, one on wss
// port 443 (the production endpoints).
logWebSocketsFor(['wss://node.example:1234/', 'wss://164.68.116.180:443/']);
after(() => { globalThis.WebSocket = savedWebSocket; });

// Proves a frame whose size cannot be read still reaches the native send and the send's result is returned: the log
// reads the size inside its own guard. Could falsely pass if the wrapper were not installed, in which case no 'sent' line
// would exist (asserted).
test('a frame size that cannot be read does not stop the send', () => {
  const lines = []; const restore = setDebugLogSink(line => lines.push(line));
  try {
    const socket = new globalThis.WebSocket('wss://node.example:1234/');
    const frame = { get byteLength() { throw new Error('size'); } };
    assert.equal(socket.send(frame), 'native-result'); assert.deepEqual(sent, [frame]);
    assert.equal(socket.send('abc'), 'native-result'); assert.ok(lines.some(line => line.includes('nodus-ws sent') && line.includes('bytes=3')));
  } finally { restore(); }
});

// Proves a socket to a configured endpoint on the DEFAULT port is logged: the endpoint is registered as the URL the
// module opens (wss, port 443, as the production endpoints are), and the host the wrapper compares is the URL's own
// normalised host, so both sides drop the default port alike. A socket to another host, and to the same host on another
// port, is still not logged. Could falsely pass if the wrapper were not installed; the 'open' line for the configured
// endpoint is asserted, and the fake fires the event itself.
test('a socket to a configured endpoint on the default port is logged, others are not', () => {
  const lines = []; const restore = setDebugLogSink(line => lines.push(line)); const first = made.length;
  try {
    for (const url of ['wss://164.68.116.180:443/', 'wss://164.68.116.180/', 'wss://198.51.100.7:443/', 'wss://164.68.116.180:8443/']) new globalThis.WebSocket(url);
    for (const socket of made.slice(first)) socket.listeners.open?.();
  } finally { restore(); }
  const opened = lines.filter(line => line.includes('nodus-ws open'));
  assert.equal(opened.length, 2, 'only the two spellings of the configured endpoint are logged');
  assert.ok(opened.every(line => /host=164\.68\.116\.180( |$)/.test(line)));
});
