import test from 'node:test';
import assert from 'node:assert/strict';
import { getAddress } from 'ethers';
import { CHAINS } from '../src/config.js';
import { balances } from '../src/adapters/solana.js';
import { checkActivity } from '../src/activity.js';

test('Solana reads and activity accept full mainnet genesis and reject truncated or wrong identities', async t => {
  const originalFetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = originalFetch; });
  let genesis = '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d';
  const methods = [];
  const call = async (_, method) => {
    methods.push(method);
    const results = {
      getGenesisHash: genesis, getBalance: { value: 1234567890 },
      getTokenAccountsByOwner: { value: [] },
      getSignatureStatuses: { value: [{ err: null, confirmationStatus: 'finalized' }] },
    };
    assert.ok(Object.hasOwn(results, method), method);
    return results[method];
  };
  globalThis.fetch = async (url, options) => {
    const body = JSON.parse(options.body);
    return Response.json({ jsonrpc: '2.0', id: body.id, result: await call(url, body.method) });
  };
  const read = () => balances('solana', 'HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk', CHAINS.solana.endpoint);
  const activity = () => checkActivity({ chain: 'solana', hash: '1'.repeat(88), endpoint: CHAINS.solana.endpoint }, { call });
  assert.equal((await read())[0].balance, '1.23456789');
  assert.equal((await activity()).status, 'confirmed');
  for (genesis of ['5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp', 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1', null]) {
    methods.length = 0;
    await assert.rejects(read(), /not Solana mainnet/);
    await assert.rejects(activity(), /Wrong network/);
    assert.deepEqual(methods, ['getGenesisHash', 'getGenesisHash']);
  }
});

test('EVM token destinations are valid addresses and DAI matches the issuer deployment', () => {
  for (const chain of ['ethereum', 'bsc']) {
    for (const token of CHAINS[chain].tokens) {
      assert.match(token.address, /^0x[0-9a-fA-F]{40}$/, `${chain} ${token.symbol}`);
      assert.doesNotThrow(() => getAddress(token.address.toLowerCase()));
    }
  }
  const dai = CHAINS.ethereum.tokens.find(token => token.symbol === 'DAI');
  assert.equal(getAddress(dai.address), '0x6B175474E89094C44Da98b954EedeAC495271d0F');
  assert.equal(dai.decimals, 18);
});
