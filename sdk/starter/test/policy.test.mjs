// Offline policy tests: runtime floors and input boundaries; no keys/network.
// No compile flags or env needed. Leaves no files. Address stub below checks
// shape only; package.smoke.mjs separately exercises the real SDK codec.
import test from 'node:test';
import assert from 'node:assert/strict';
import { assertNode } from '../src/version.mjs';
import { integer, configBase, vaultArgs, escrowArgs, contractAddress } from '../src/config.mjs';

const address = n => `0x${String(n).repeat(64)}`;
const sdk = {
  parseAddress(value) {
    if (typeof value !== 'string' || !/^0x[0-9a-f]{64}$/.test(value)) throw new Error('32-byte address required');
    return value.slice(2);
  },
  resolveNetwork: () => ({ chainId: 'a'.repeat(64) }),
  resolveEvmNetwork: () => ({ enabled: true })
};

test('only patched supported Node majors pass; malformed and prerelease versions refuse', () => {
  for (const version of ['22.23.4', 'v22.24.0', '24.22.1', '24.23.0']) assert.doesNotThrow(() => assertNode(version));
  for (const version of ['22.23.3', '22.12.0', '24.22.0', '24.21.99', '20.99.99', '23.0.0', '26.12.1', '24.22.1-rc.1', 'garbage']) {
    assert.throws(() => assertNode(version), /Node.js/);
  }
});

test('integer input never passes through floating point or truncates', () => {
  assert.equal(integer('9007199254740993', 'amount'), 9007199254740993n);
  for (const value of [1, 0.5, '01', '-1', '+1', '1e3', '1.0', '', ' 1', String(2n ** 256n)]) {
    assert.throws(() => integer(value, 'amount'), /amount/);
  }
  assert.throws(() => integer('0', 'amount', { positive: true }), /amount/);
  assert.throws(() => integer(String(2n ** 64n), 'raw', { bits: 64 }), /raw/);
});

test('config refuses unknown/secret keys and invalid fees; network validation delegated to SDK', () => {
  assert.equal(configBase({ version: 1, maxFeeRaw: '1000' }, sdk).maxFee, 1000n);
  assert.throws(() => configBase({ version: 1, maxFeeRaw: 1000 }, sdk), /maxFeeRaw/);
  assert.throws(() => configBase({ version: 1, maxFeeRaw: '1000', phrase: 'never log this' }, sdk), /Unsupported config field/);
  assert.throws(() => configBase({ version: 2, maxFeeRaw: '1000' }, sdk), /version/);
});

test('vault constructor refuses wrong address size, duplicate/zero owners and impossible threshold', () => {
  const config = { vault: { owners: [address(1), address(2)], threshold: '2' } };
  assert.deepEqual(vaultArgs(config, sdk), [[address(1), address(2)], 2n]);
  for (const owners of [[], [address(0)], [address(1), address(1)], [`0x${'11'.repeat(20)}`], Array.from({ length: 33 }, () => address(1))]) {
    assert.throws(() => vaultArgs({ vault: { owners, threshold: '1' } }, sdk));
  }
  assert.throws(() => vaultArgs({ vault: { ...config.vault, threshold: '3' } }, sdk), /threshold/);
  assert.throws(() => contractAddress({ vault: { address: 'REPLACE_ME' } }, 'vault', sdk), /32-byte/);
});

test('escrow constructor enforces parties, positive quantized amounts and bounded sum', () => {
  const escrow = { payer: address(1), payee: address(2), arbiter: address(3), amountsWei: ['10000000000', '20000000000'], deadline: '2000000000' };
  assert.deepEqual(escrowArgs({ escrow }, sdk), [address(1), address(2), address(3), [10000000000n, 20000000000n], 2000000000n]);
  for (const change of [{ payee: address(1) }, { arbiter: address(0) }, { amountsWei: [] }, { amountsWei: ['0'] }, { amountsWei: ['1'] }, { deadline: '0' }]) {
    assert.throws(() => escrowArgs({ escrow: { ...escrow, ...change } }, sdk));
  }
});
