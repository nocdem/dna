import test from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519';
import { getAddressEncoder, getCompiledTransactionMessageDecoder, decompileTransactionMessage } from '@solana/kit';
import { parseTransferSolInstruction } from '@solana-program/system';
import { TronWeb } from 'tronweb';
import { CHAINS } from '../../src/config.js';
import { activityKeyFor, parseActivity, historyKeyFor, parseHistory } from '../../src/activity-storage.js';
import { parseVault, VAULT_KEY, ACTIVITY_KEY, HISTORY_KEY } from '../../src/vault.js';
import { AUTO_LOCK_TIMEOUT_ALARM } from '../src/background/auto-lock-alarm.js';
import { setup, deferred, phrase, password, unlockOptions } from './solana-tron-fixture.js';

// Environment/cleanup: fixture above; no real RPC, no files written, no skips.
// Checking symbols alone could pass with placeholder balances: assert amounts.
test('both chains use mainnet adapters for native and every configured token balance', async t => {
  const { background, state, calls, keysUsed } = await setup(t);
  assert.deepEqual((await background.solana.getBalances()).map(r => [r.symbol, r.balance]), [['SOL', '10.0'], ['USDT', '250.0'], ['USDC', '250.0']]);
  assert.deepEqual((await background.tron.getBalances()).map(r => [r.symbol, r.balance]), [['TRX', '123.0'], ['USDT', '250.0'], ['USDC', '250.0'], ['USDD', '250.0']]);
  assert.deepEqual(keysUsed, []);
  assert.equal(background.solana.getReceiveAddress(), state.addresses.solana);
  assert.equal(background.tron.getReceiveAddress(), state.addresses.tron);
  assert.ok(calls.some(c => c.body.method === 'getGenesisHash'));
  state.wrongNetwork = true;
  for (const chain of ['solana', 'tron']) await assert.rejects(background[chain].getBalances(), /mainnet/);
});

// Real signatures and decoded fields are checked, so a fake hash or a wrong
// recipient/asset/amount cannot satisfy the confirm-path assertions.
test('native and all token reviews preserve web review fields and confirm exactly once', async t => {
  const { background, state, broadcasts, keysUsed, values, calls } = await setup(t);
  for (const chain of ['solana', 'tron']) {
    const config = CHAINS[chain], from = state.addresses[chain], to = state.recipients[chain];
    for (const symbol of [config.symbol, ...config.tokens.map(t => t.symbol)]) {
      const before = broadcasts.length;
      const review = await background[chain].prepareSend({ symbol, to, amount: '1', endpoint: 'https://untrusted.example' });
      assert.equal(broadcasts.length, before);
      assert.deepEqual(review.review, [
        ['Network', `${config.name} mainnet`], ['From', from], ['To', to], ['Asset', symbol], ['Amount', '1'], ['Network fee', review.fee],
      ]);
      assert.ok(Number.isFinite(review.expiresAt));
      if (chain === 'solana') assert.match(review.fee, symbol === 'SOL' ? /^0.000005 SOL fee$/ : /SOL account rent/);
      else assert.match(review.fee, symbol === 'TRX' ? /bandwidth and recipient activation/ : /Energy fee limit: 100 TRX/);
      const hash = await background[chain].confirmSend(review.id);
      assert.equal(broadcasts.length, before + 1);
      await assert.rejects(background[chain].confirmSend(review.id), /already closed/);
      const { tx } = broadcasts.at(-1);
      if (chain === 'solana') {
        for (const [signer, signature] of Object.entries(tx.signatures)) assert.ok(ed25519.verify(signature, tx.messageBytes, getAddressEncoder().encode(signer)));
        const instructions = decompileTransactionMessage(getCompiledTransactionMessageDecoder().decode(tx.messageBytes)).instructions;
        if (symbol === 'SOL') {
          const transfer = parseTransferSolInstruction(instructions[0]); assert.equal(transfer.data.amount, 1000000000n); assert.equal(transfer.accounts.destination.address, to);
        } else {
          assert.equal(instructions.length, 2); assert.equal(instructions[1].accounts[1].address, config.tokens.find(t => t.symbol === symbol).address);
          assert.equal(Buffer.from(instructions[1].data).readBigUInt64LE(1), 1000000n);
        }
      } else {
        assert.equal(tx.txID, hash);
        const value = tx.raw_data.contract[0].parameter.value;
        assert.equal(value.owner_address.toLowerCase(), TronWeb.address.toHex(from).toLowerCase());
        if (symbol === 'TRX') { assert.equal(value.amount, 1000000); assert.equal(value.to_address.toLowerCase(), TronWeb.address.toHex(to).toLowerCase()); }
        else assert.equal(value.contract_address.toLowerCase(), TronWeb.address.toHex(config.tokens.find(t => t.symbol === symbol).address).toLowerCase());
      }
      const id = parseVault(values[VAULT_KEY]).id, key = await activityKeyFor(phrase, id);
      assert.ok((await parseActivity(values[ACTIVITY_KEY], id, state.addresses, key)).some(r => r.hash === hash && r.symbol === symbol));
    }
  }
  assert.ok(keysUsed.includes('getSolanaKeypair')); assert.ok(keysUsed.includes('getTronPrivateKey'));
  const text = JSON.stringify([values, calls.map(c => c.body)]);
  assert.equal(text.includes(phrase), false); assert.equal(text.includes(background.walletKeys.getTronPrivateKey()), false);
});

// Hold an earlier activity save after serialization, then append a real signed
// send before that save completes. It must reach storage before broadcast and
// remain in live activity. Explicit gates control the overlap; no polling or live network.
test('an in-flight activity save preserves the next signed send on both chains', async t => {
  for (const chain of ['solana', 'tron']) {
    const { background, state, values, broadcasts } = await setup(t);
    const activity = background.nodus.chainActivity(chain), appended = deferred();
    const append = activity.append;
    t.mock.method(activity, 'append', (...args) => {
      const row = append(...args); appended.resolve(); return row;
    });
    t.mock.method(background.nodus, 'chainActivity', requested => {
      assert.equal(requested, chain); return activity;
    });
    const symbol = CHAINS[chain].symbol, to = state.recipients[chain];
    const review = await background[chain].prepareSend({ symbol, to, amount: '1' });
    const id = parseVault(values[VAULT_KEY]).id, key = await activityKeyFor(phrase, id);
    state.entered = deferred(); state.saveGate = deferred();
    const saving = activity.persist();
    await state.entered.promise;
    const sending = background[chain].confirmSend(review.id);
    await appended.promise;
    assert.equal(broadcasts.length, 0, 'the signed send waits for its queued save');
    state.saveGate.resolve();
    const [, hash] = await Promise.all([saving, sending]);
    assert.equal(broadcasts.length, 1);
    for (const rows of [activity.rows(), await parseActivity(values[ACTIVITY_KEY], id, state.addresses, key)]) {
      const row = rows.find(r => r.chain === chain && r.hash === hash);
      assert.ok(row, `${chain} signed record survives the earlier save`);
      assert.equal(row.address, state.addresses[chain]); assert.equal(row.to, to);
      assert.equal(row.symbol, symbol); assert.equal(row.amount, '1');
    }
    await assert.rejects(background[chain].confirmSend(review.id), /already closed/);
  }
});

// Review-only tests miss cancellation, expired-review refusal and server-side
// input validation; no failed path below may reach broadcast.
test('cancel, expiry, invalid inputs and wrong-network prepares never broadcast', async t => {
  const { background, state, broadcasts } = await setup(t);
  for (const chain of ['solana', 'tron']) {
    const fields = { symbol: CHAINS[chain].symbol, to: state.recipients[chain], amount: '1' };
    const cancelled = await background[chain].prepareSend(fields); background[chain].cancelSend(cancelled.id);
    await assert.rejects(background[chain].confirmSend(cancelled.id), /closed/);
    const expired = await background[chain].prepareSend(fields), now = Date.now;
    const mock = t.mock.method(Date, 'now', () => expired.expiresAt);
    await assert.rejects(background[chain].confirmSend(expired.id), /expired/); mock.mock.restore(); assert.equal(Date.now, now);
    await assert.rejects(background[chain].prepareSend({ ...fields, amount: '0' }));
    await assert.rejects(background[chain].prepareSend({ ...fields, symbol: 'UNKNOWN' }), /Unsupported asset/);
    state.wrongNetwork = true; await assert.rejects(background[chain].prepareSend(fields), /mainnet/); state.wrongNetwork = false;
  }
  assert.equal(broadcasts.length, 0);
});

// Pins the complete named-recipient branch, including the module-checked
// profile field and the web review's source, owner, address and name warning.
test('Solana and TRON chain-name reviews include the web wallet signed-profile fields', async t => {
  const { background, state, broadcasts } = await setup(t);
  for (const chain of ['solana', 'tron']) {
    const review = await background[chain].prepareSend({ symbol: CHAINS[chain].symbol, to: 'alice', amount: '1' });
    const entries = Object.fromEntries(review.review);
    assert.equal(entries['To (chain name)'], 'alice'); assert.equal(entries.To, state.recipients[chain]);
    assert.equal(entries['Name owner (Nodus ID)'], state.addresses.nodus);
    assert.match(entries['Recipient source'], /owner’s signed profile.*state of block 2/);
    assert.match(entries['Name check'], /Names can look alike/);
    background[chain].cancelSend(review.id);
  }
  assert.equal(broadcasts.length, 0);
});

// Pins both lock entrypoints and a late adapter continuation. Checking only
// isUnlocked would miss an old review sending after a later successful unlock.
test('manual and alarm locks stop reviews and delayed confirm work across unlock', async t => {
  for (const chain of ['solana', 'tron']) for (const mode of ['manual', 'alarm']) {
    const { background, fixture, state, broadcasts } = await setup(t);
    const secret = background.walletKeys.getSolanaKeypair().secretKey;
    const review = await background[chain].prepareSend({ symbol: CHAINS[chain].symbol, to: state.recipients[chain], amount: '1' });
    const other = chain === 'solana' ? 'tron' : 'solana';
    const dormant = await background[other].prepareSend({ symbol: CHAINS[other].symbol, to: state.recipients[other], amount: '1' });
    state.entered = deferred(); state.readGate = deferred();
    if (chain === 'solana') state.pauseMethod = 'getBlockHeight'; else state.pausePath = '/wallet/getblockbynum';
    const sending = background[chain].confirmSend(review.id); const rejected = assert.rejects(sending, /locked|cancelled|abort/i);
    await state.entered.promise;
    if (mode === 'manual') await background.lock(); else await fixture.alarms.onAlarm.emit({ name: AUTO_LOCK_TIMEOUT_ALARM });
    assert.ok(secret.every(byte => byte === 0));
    assert.throws(() => background.walletKeys.getSolanaKeypair(), /locked/);
    assert.throws(() => background.walletKeys.getTronPrivateKey(), /locked/);
    await assert.rejects(background[chain].getBalances(), /locked/);
    await assert.rejects(background[chain].prepareSend({}), /locked/);
    await assert.rejects(background[chain].getHistory(), /locked/);
    assert.throws(() => background[chain].getReceiveAddress(), /locked/);
    await background.unlock(password, unlockOptions);
    state.readGate.resolve(); await rejected;
    assert.equal(broadcasts.length, 0);
    await assert.rejects(background[chain].confirmSend(review.id), /closed/);
    await assert.rejects(background[other].confirmSend(dormant.id), /closed/);
    await background.lock();
  }
});

// Storage yields after signing. The adapter's final assertWalletActive must
// still check the extension session after the durable-record callback resolves.
test('lock during persistence and failed persistence prevent both broadcasts', async t => {
  for (const chain of ['solana', 'tron']) {
    const { background, state, broadcasts } = await setup(t);
    const fields = { symbol: CHAINS[chain].symbol, to: state.recipients[chain], amount: '1' };
    state.failSave = true;
    const failed = await background[chain].prepareSend(fields);
    await assert.rejects(background[chain].confirmSend(failed.id), /persistence failed/); assert.equal(broadcasts.length, 0);
    state.failSave = false; state.entered = deferred(); state.saveGate = deferred();
    const review = await background[chain].prepareSend(fields);
    const sending = background[chain].confirmSend(review.id), rejected = assert.rejects(sending, /locked/);
    await state.entered.promise; await background.lock(); state.saveGate.resolve(); await rejected;
    assert.equal(broadcasts.length, 0); await background.lock();
  }
});

// A pending prepare/balance/history must reject at lock, even if its fake
// transport ignores abort; its late result cannot revive the closed session.
test('lock drops pending read and prepare results without additional key access', async t => {
  for (const chain of ['solana', 'tron']) for (const kind of ['balance', 'prepare', 'history']) {
    const { background, state, broadcasts, keysUsed } = await setup(t);
    state.entered = deferred(); state.readGate = deferred();
    if (chain === 'solana') state.pauseMethod = kind === 'balance' ? 'getBalance' : kind === 'prepare' ? 'getLatestBlockhash' : 'getSignaturesForAddress';
    else state.pausePath = kind === 'balance' ? `/v1/accounts/${state.addresses.tron}` : kind === 'prepare' ? '/wallet/getblock' : `/v1/accounts/${state.addresses.tron}/transactions`;
    const request = kind === 'balance' ? background[chain].getBalances() : kind === 'history' ? background[chain].getHistory()
      : background[chain].prepareSend({ symbol: CHAINS[chain].symbol, to: state.recipients[chain], amount: '1' });
    const rejected = assert.rejects(request, /locked/); await state.entered.promise; await background.lock(); await rejected;
    const used = keysUsed.length; state.readGate.resolve();
    // Drain promise continuations after the deliberately late fake response.
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(keysUsed.length, used); assert.equal(broadcasts.length, 0);
  }
});

// The real adapters reach the fake broadcast and then fail: the durable
// identifier remains trackable and the consumed review cannot send again.
test('ambiguous broadcasts retain encrypted activity and never retry the review', async t => {
  const { background, state, broadcasts, values } = await setup(t);
  state.failBroadcast = true;
  for (const chain of ['solana', 'tron']) {
    const review = await background[chain].prepareSend({ symbol: CHAINS[chain].symbol, to: state.recipients[chain], amount: '1' });
    await assert.rejects(background[chain].confirmSend(review.id), error => {
      assert.equal(error.data.activityTracked, true); assert.match(error.message, /broadcast uncertain|RPC unavailable/); return true;
    });
    await assert.rejects(background[chain].confirmSend(review.id), /closed/);
    const id = parseVault(values[VAULT_KEY]).id;
    assert.ok((await parseActivity(values[ACTIVITY_KEY], id, state.addresses, await activityKeyFor(phrase, id))).some(row => row.chain === chain));
  }
  assert.deepEqual(broadcasts.map(b => b.chain), ['solana', 'tron']);
});

// Account history is read through the real parsers; known Solana signatures
// must not refetch transactions. Pending records survive an unavailable source.
test('history uses web parsers, encrypted cache and activity with no UI key material', async t => {
  const { background, client, values, calls, state } = await setup(t);
  for (const chain of ['solana', 'tron']) {
    const review = await background[chain].prepareSend({ symbol: CHAINS[chain].symbol, to: state.recipients[chain], amount: '1' });
    await background[chain].confirmSend(review.id);
    const history = await background[chain].getHistory();
    assert.equal(history.rows[0].amount, '1.0'); assert.equal(history.rows[0].chain, chain);
    assert.ok(history.status.includes(chain === 'solana' ? 'Solana RPC' : 'TronGrid'));
    const reads = calls.filter(c => c.body.method === 'getTransaction').length;
    await background[chain].getHistory(); assert.equal(calls.filter(c => c.body.method === 'getTransaction').length, reads);
    const rereadAt = Date.now() + 31000, advancing = t.mock.method(Date, 'now', () => rereadAt);
    await background[chain].getHistory({ manual: true }); advancing.mock.restore();
    assert.equal(calls.filter(c => c.body.method === 'getTransaction').length, reads, 'known signatures skip transaction reads even on a fresh source read');
    state.failHistory = true;
    // A failed manual read after the web wallet's thirty-second cooldown
    // must keep cached rows and pending local activity.
    const future = rereadAt + 31000, mock = t.mock.method(Date, 'now', () => future);
    const failed = await background[chain].getHistory({ manual: true }); mock.mock.restore(); state.failHistory = false;
    assert.ok(failed.error); assert.ok(failed.local.length); assert.deepEqual(failed.rows, history.rows);
    const id = parseVault(values[VAULT_KEY]).id;
    const saved = await parseHistory(values[HISTORY_KEY], id, await historyKeyFor(phrase, id));
    assert.deepEqual(saved[chain].rows, history.rows);
    const visible = JSON.stringify([review, history, await client.request('getState')]);
    for (const forbidden of [phrase, background.walletKeys.getTronPrivateKey(), 'secretKey', 'tronPrivateKey', 'messageBytes', 'raw_data_hex']) assert.equal(visible.includes(forbidden), false, forbidden);
  }
});

// Reopening exercises actual parseActivity/parseHistory, not only in-memory
// rows. An unreadable activity envelope blocks sends until explicit discard.
test('unlock restores encrypted history and shares the web activity corruption gate', async t => {
  const { background, state, values, calls } = await setup(t);
  for (const chain of ['solana', 'tron']) await background[chain].getHistory();
  const reads = calls.length;
  await background.lock(); await background.unlock(password, unlockOptions);
  for (const chain of ['solana', 'tron']) assert.ok((await background[chain].getHistory()).rows.length);
  assert.equal(calls.length, reads);
  await background.lock(); values[ACTIVITY_KEY] = 'invalid encrypted activity'; await background.unlock(password, unlockOptions);
  for (const chain of ['solana', 'tron']) await assert.rejects(background[chain].prepareSend({ symbol: CHAINS[chain].symbol, to: state.recipients[chain], amount: '1' }), /discard the unreadable history/);
  await background.nodus.discardActivity();
  for (const chain of ['solana', 'tron']) {
    const review = await background[chain].prepareSend({ symbol: CHAINS[chain].symbol, to: state.recipients[chain], amount: '1' });
    background[chain].cancelSend(review.id);
  }
});

// Imported API wiring, rather than a renderer-only fixture, must provide the
// requested chain operations. The site engine still has no such methods.
test('trusted API routes both chains and sites cannot call internal chain methods', async t => {
  const { background, client, state } = await setup(t);
  for (const [chain, prefix] of [['solana', 'Solana'], ['tron', 'Tron']]) {
    assert.ok((await client.request(`get${prefix}Balances`)).length);
    const review = await client.request(`prepare${prefix}Send`, [{ symbol: CHAINS[chain].symbol, to: state.recipients[chain], amount: '1' }]);
    await client.request(`cancel${prefix}Send`, [review.id]);
    await assert.rejects(client.request(`confirm${prefix}Send`, [review.id]), /closed/);
    assert.ok((await client.request(`get${prefix}History`)).status);
    const { engine } = background.engine.setupProviderEngineEip1193({ origin: 'https://site.example', subjectType: 'website' });
    try { assert.ok((await engine.handle({ id: 1, jsonrpc: '2.0', method: `prepare${prefix}Send`, params: [] })).error); }
    finally { engine.destroy(); }
  }
});
