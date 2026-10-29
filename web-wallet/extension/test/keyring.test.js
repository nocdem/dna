import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { getAddress, getBytes, Transaction, verifyMessage, verifyTypedData } from 'ethers';
import { Messenger } from '@metamask/messenger';
import { deriveWallet, disposeWallet } from '../../src/keys.js';
import { createLockCoordinator } from '../src/background/lock.js';
import { createWalletKeys } from '../src/background/wallet-keys.js';
import { createKeyring } from '../src/background/keyring.js';

// Node >=22.14, pinned packages and existing CPUNK WASM; offline, no persistent output.
const { vectors } = JSON.parse(readFileSync(new URL('../../test/fixtures/nodus-addresses.json', import.meta.url)));
const cpunkWasmBytes = readFileSync(new URL('../../src/cpunk/legacy-dilithium.wasm', import.meta.url));
const messageTypes = { Message: [{ name: 'text', type: 'string' }] };
const typed = { domain: { name: 'Nodus extension test', version: '1', chainId: 1 },
  types: { EIP712Domain: [{ name: 'name', type: 'string' }, { name: 'version', type: 'string' }, { name: 'chainId', type: 'uint256' }], ...messageTypes },
  primaryType: 'Message', message: { text: 'public fixture' } };
const transaction = () => ({ nonce: 0, chainId: 1, type: 0, gasPrice: 1000000000n, gasLimit: 21000n, to: '0x0000000000000000000000000000000000000001', value: 123n });
function setup(messenger) {
  const lockCoordinator = createLockCoordinator();
  const walletKeys = createWalletKeys({ lockCoordinator, consumeNodusSeed: () => {} });
  const keyring = createKeyring({ lockCoordinator, messenger, getWallet: walletKeys.getEvmWallet });
  const open = phrase => lockCoordinator.unlock(() => walletKeys.unlock(phrase, { cpunkWasmBytes }));
  return { lockCoordinator, walletKeys, keyring, open };
}

// Proves all vector addresses and a fixed known address; comparing two derivations alone could share a wrong path.
test('one ethers account equals the web-wallet EVM address for every Nodus vector', async () => {
  const { lockCoordinator, keyring, open } = setup();
  try {
    for (const { phrase } of vectors) {
      const wallet = deriveWallet(phrase);
      try {
        await open(`  ${phrase.toUpperCase()}  `);
        assert.deepEqual((await keyring.getAccounts()).map(getAddress), [wallet.addresses.ethereum]);
        assert.equal(wallet.addresses.ethereum, wallet.addresses.bsc);
        if (phrase === vectors[0].phrase) assert.equal(getAddress((await keyring.getAccounts())[0]), '0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb');
      } finally { disposeWallet(wallet); await lockCoordinator.lock(); }
    }
    await assert.rejects(open('abandon '.repeat(12)), /24-word/);
  } finally { await lockCoordinator.lock(); }
});

// Proves real ethers signatures, all lock guards and private-action isolation; rejection-only checks could hide an unusable signer.
test('personal, typed and transaction signing recover the account and are all guarded', async () => {
  const messenger = new Messenger({ namespace: 'KeyringController' });
  const { lockCoordinator, keyring, open } = setup(messenger);
  try {
    await open(vectors[0].phrase); const from = (await keyring.getAccounts())[0];
    const signature = await messenger.call('KeyringController:signPersonalMessage', { from, data: '0x1234' });
    assert.equal(verifyMessage(getBytes('0x1234'), signature), getAddress(from));
    const typedSignature = await messenger.call('KeyringController:signTypedMessage', { from, data: typed }, 'V4');
    assert.equal(verifyTypedData(typed.domain, messageTypes, typed.message, typedSignature), getAddress(from));
    const decoded = Transaction.from(await messenger.call('KeyringController:signTransaction', transaction(), from));
    assert.equal(decoded.from, getAddress(from)); assert.equal(decoded.value, 123n);
    assert.equal(decoded.to, '0x0000000000000000000000000000000000000001');
    assert.throws(() => messenger.call('KeyringController:getState'));
    assert.throws(() => messenger.call('KeyringController:exportSeedPhrase', 'public-password'));
    assert.deepEqual(await lockCoordinator.lock(), []);
    await assert.rejects(keyring.getAccounts(), /locked/i);
    await assert.rejects(messenger.call('KeyringController:signPersonalMessage', { from, data: '0x1234' }), /locked/i);
    await assert.rejects(messenger.call('KeyringController:signTypedMessage', { from, data: typed }, 'V4'), /locked/i);
    await assert.rejects(messenger.call('KeyringController:signTransaction', transaction(), from), /locked/i);
    await assert.rejects(setup().keyring.getAccounts(), /locked/i);
  } finally { await lockCoordinator.lock(); }
});

// Proves a queued ethers result cannot escape across lock/re-unlock; requests started after lock miss captured-wallet work.
test('a pending ethers signature cannot escape after lock and a new unlock', async t => {
  const { lockCoordinator, keyring, walletKeys, open } = setup();
  await open(vectors[0].phrase); const wallet = walletKeys.getEvmWallet(), from = wallet.evm.address;
  const sign = wallet.evm.signMessage.bind(wallet.evm);
  let release, entered; const waiting = new Promise(resolve => { entered = resolve; });
  t.mock.method(wallet.evm, 'signMessage', async (...args) => { const signed = await sign(...args); entered(); await new Promise(resolve => { release = resolve; }); return signed; });
  const rejected = assert.rejects(keyring.signPersonalMessage({ from, data: '0x1234' }), /locked/i);
  await waiting;
  try { await lockCoordinator.lock(); assert.equal(wallet.evm, null); await open(vectors[0].phrase); }
  finally { release(); }
  await rejected; await lockCoordinator.lock();
});

// Proves a lock during derivation disposes the late wallet; a lock after completion misses resurrection.
test('lock while web-wallet derivation waits cannot publish EVM accounts', async () => {
  const lockCoordinator = createLockCoordinator();
  let entered, release; const waiting = new Promise(resolve => { entered = resolve; });
  const walletKeys = createWalletKeys({ lockCoordinator, consumeNodusSeed: async () => { entered(); await new Promise(resolve => { release = resolve; }); } });
  const keyring = createKeyring({ lockCoordinator, getWallet: walletKeys.getEvmWallet });
  const rejected = assert.rejects(lockCoordinator.unlock(() => walletKeys.unlock(vectors[0].phrase, { cpunkWasmBytes })), /locked/i);
  await waiting; try { await lockCoordinator.lock(); } finally { release(); }
  await rejected; await assert.rejects(keyring.getAccounts(), /locked/i); assert.throws(walletKeys.getEvmWallet, /locked/i);
});
