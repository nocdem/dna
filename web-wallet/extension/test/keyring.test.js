import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { getAddress, getBytes, hexlify, Transaction, verifyMessage, verifyTypedData } from 'ethers';
import { LegacyTransaction } from '@ethereumjs/tx';
import { Messenger } from '@metamask/messenger';
import { KeyringController } from '@metamask/keyring-controller';
import { deriveWallet, disposeWallet } from '../../src/keys.js';
import { createLockCoordinator } from '../src/background/lock.js';
import { createKeyring } from '../src/background/keyring.js';

// Node >=22.14, installed pinned packages; offline, no files/storage left behind.
// Public vectors: test/nodus-address.test.js + fixtures/nodus-addresses.json;
// the first vector's fixed EVM address is also in test/wallet.test.js.
const { vectors } = JSON.parse(readFileSync(new URL('../../test/fixtures/nodus-addresses.json', import.meta.url)));
const password = 'public-test-password-123';
const messageTypes = { Message: [{ name: 'text', type: 'string' }] };
// eth-sig-util 9.0.0 sign-typed-data.js:40-50 requires primaryType; the domain
// fields must be included for ethers' independent domain hash to match.
const typed = {
  domain: { name: 'Nodus extension test', version: '1', chainId: 1 },
  types: { EIP712Domain: [{ name: 'name', type: 'string' }, { name: 'version', type: 'string' }, { name: 'chainId', type: 'uint256' }], ...messageTypes },
  primaryType: 'Message', message: { text: 'public fixture' },
};
const transaction = () => LegacyTransaction.fromTxData({ nonce: 0, gasPrice: 1000000000n, gasLimit: 21000n, to: '0x0000000000000000000000000000000000000001', value: 123n });
async function open(lockCoordinator, keyring, phrase = vectors[0].phrase) {
  await lockCoordinator.unlock(() => keyring.unlock(phrase, password));
  return (await keyring.getAccounts())[0];
}

// Proves first-account parity across existing phrases; comparing only two derivations without the fixed address could share a wrong path.
test('one HD account equals the web-wallet EVM address for every Nodus vector', async () => {
  const lockCoordinator = createLockCoordinator(), keyring = createKeyring({ lockCoordinator });
  try {
    for (const { phrase } of vectors) {
      const wallet = deriveWallet(phrase);
      try {
        await open(lockCoordinator, keyring, `  ${phrase.toUpperCase()}  `);
        assert.deepEqual((await keyring.getAccounts()).map(getAddress), [wallet.addresses.ethereum]);
        assert.equal(wallet.addresses.ethereum, wallet.addresses.bsc);
        if (phrase === vectors[0].phrase) assert.equal(getAddress((await keyring.getAccounts())[0]), '0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb');
      } finally { disposeWallet(wallet); await lockCoordinator.lock(); }
    }
    await assert.rejects(keyring.unlock('abandon '.repeat(12), password), /24-word/);
  } finally { await lockCoordinator.lock(); }
});

// Proves all three messenger actions use the real HD signer and refuse after lock; rejection-only checks could pass with an unusable signer.
test('personal, typed and transaction signing recover the account and are all guarded', async () => {
  const lockCoordinator = createLockCoordinator(), messenger = new Messenger({ namespace: 'KeyringController' });
  const keyring = createKeyring({ lockCoordinator, messenger });
  try {
    const from = await open(lockCoordinator, keyring);
    const signature = await messenger.call('KeyringController:signPersonalMessage', { from, data: '0x1234' });
    assert.equal(verifyMessage(getBytes('0x1234'), signature), getAddress(from));
    const typedSignature = await messenger.call('KeyringController:signTypedMessage', { from, data: typed }, 'V4');
    assert.equal(verifyTypedData(typed.domain, messageTypes, typed.message, typedSignature), getAddress(from));
    const signed = await messenger.call('KeyringController:signTransaction', transaction(), from);
    const decoded = Transaction.from(hexlify(signed.serialize()));
    assert.equal(decoded.from, getAddress(from)); assert.equal(decoded.value, 123n);
    assert.equal(decoded.to, '0x0000000000000000000000000000000000000001');
    assert.throws(() => messenger.call('KeyringController:getState'));
    assert.throws(() => messenger.call('KeyringController:exportSeedPhrase', password));
    assert.deepEqual(await lockCoordinator.lock(), []);
    await assert.rejects(keyring.getAccounts(), /locked/i);
    await assert.rejects(messenger.call('KeyringController:signPersonalMessage', { from, data: '0x1234' }), /locked/i);
    await assert.rejects(messenger.call('KeyringController:signTypedMessage', { from, data: typed }, 'V4'), /locked/i);
    await assert.rejects(messenger.call('KeyringController:signTransaction', transaction(), from), /locked/i);
    const restarted = createKeyring({ lockCoordinator: createLockCoordinator() });
    await assert.rejects(restarted.getAccounts(), /locked/i);
  } finally { await lockCoordinator.lock(); }
});

// Proves a lock revokes a signature already waiting inside the controller, even after re-unlock; a request started after lock would miss the captured-keyring case.
test('a pending controller signature cannot escape after lock and a new unlock', async t => {
  const lockCoordinator = createLockCoordinator(), keyring = createKeyring({ lockCoordinator });
  const from = await open(lockCoordinator, keyring);
  const sign = KeyringController.prototype.signPersonalMessage;
  let release, entered;
  const waiting = new Promise(resolve => { entered = resolve; });
  t.mock.method(KeyringController.prototype, 'signPersonalMessage', async function (...args) {
    const signed = await sign.apply(this, args);
    entered(); await new Promise(resolve => { release = resolve; }); return signed;
  });
  const signing = keyring.signPersonalMessage({ from, data: '0x1234' });
  const rejected = assert.rejects(signing, /locked/i);
  await waiting;
  try {
    await lockCoordinator.lock();
    await open(lockCoordinator, keyring);
  } finally { release(); }
  await rejected;
  await lockCoordinator.lock();
});

// Proves late restore completion calls setLocked and cannot publish accounts; a lock only after restore resolves would miss resurrection.
test('lock while HD restore is pending disposes the late controller', async t => {
  const lockCoordinator = createLockCoordinator(), keyring = createKeyring({ lockCoordinator });
  const restore = KeyringController.prototype.createNewVaultAndRestore;
  let release, entered, restored;
  const waiting = new Promise(resolve => { entered = resolve; });
  t.mock.method(KeyringController.prototype, 'createNewVaultAndRestore', async function (...args) {
    await restore.apply(this, args); restored = this;
    entered(); await new Promise(resolve => { release = resolve; });
  });
  const unlocking = open(lockCoordinator, keyring), rejected = assert.rejects(unlocking, /locked/i);
  await waiting;
  try { await lockCoordinator.lock(); } finally { release(); }
  await rejected;
  assert.equal(restored.state.isUnlocked, false);
  assert.deepEqual(restored.state.keyrings, []);
  await assert.rejects(keyring.getAccounts(), /locked/i);
});
