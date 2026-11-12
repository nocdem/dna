// Proves the start-view helper reads only the query `view=connect` of a wallet page address, and nothing else:
// the notification click opens `home.html?view=connect`, and the page must open on Connect from that query alone.
// Node >=22.14, no flags, network or files. It falsely passes only if a caller sends a value the helper does not
// see (the page passes `window.location.search`); ui-render.test.js proves that wiring with a fake page.
import test from 'node:test';
import assert from 'node:assert/strict';
import { startView } from '../src/ui/start-view.js';

test('only the query view=connect selects the Connect start view', () => {
  assert.equal(startView('?view=connect'), 'connect');
  assert.equal(startView('?a=1&view=connect'), 'connect');
});

// The wallet screen routes on the hash, so a hash must never select a start view; an unknown value, no value and a
// missing search string all give null (the wallet as today).
test('an empty, unknown, hash or missing search gives no start view', () => {
  for (const value of ['', '?', '?view=x', '?view=', '#connect', '#view=connect', 'view=connect-more', undefined, null]) {
    assert.equal(startView(value), null, String(value));
  }
});
