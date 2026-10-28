import { getAddress, getBytes, isHexString, toUtf8Bytes, TypedDataEncoder } from 'ethers';
import { rpcErrors } from '@metamask/rpc-errors';

// Operator 2026-10-28: "Web cüzdanınkini kullan". Custody/derivation is
// src/keys.js:21-40 at 85506fccb352392f59f1e4d1140dd0a9452b3c1c.
// This facade retains only guards, never another controller, vault or signer.
export function createKeyring({ lockCoordinator, getWallet, messenger }) {
  let generation = 0;
  lockCoordinator.register('keyring', { lock() { generation++; } });

  async function call(operation, from) {
    lockCoordinator.assertUnlocked();
    const wallet = getWallet(), started = generation;
    function assertCurrent() {
      lockCoordinator.assertUnlocked();
      if (generation !== started || wallet.locked || wallet !== getWallet()) throw new Error('Wallet is locked.');
    }
    assertCurrent();
    if (from !== undefined && getAddress(from) !== wallet.evm.address) throw rpcErrors.invalidParams('Account does not match the wallet.');
    try { return await operation(wallet.evm); }
    finally { assertCurrent(); }
  }

  const actions = {
    // ethers 6.17.0 lib.esm/wallet/base-wallet.js:73-82 implements ERC-191.
    // Pinned middleware wallet.mjs:297-347 supplies personal_sign's data/from.
    signPersonalMessage: params => call(evm => {
      if (typeof params.data !== 'string') throw rpcErrors.invalidParams('Expected a message string.');
      return evm.signMessage(isHexString(params.data) ? getBytes(params.data) : toUtf8Bytes(params.data));
    }, params?.from),
    // ethers 6.17.0 base-wallet.js:105-120, hash/typed-data.js:163-234.
    // EIP712Domain is passed separately; never construct a hash or signature here.
    signTypedMessage: (params, version = 'V4') => call(evm => {
      if (version !== 'V4') throw rpcErrors.methodNotSupported();
      let typed;
      try { typed = typeof params.data === 'string' ? JSON.parse(params.data) : params.data; }
      catch { throw rpcErrors.invalidParams('Invalid typed data.'); }
      const { EIP712Domain: _domain, ...types } = typed.types;
      if (TypedDataEncoder.from(types).primaryType !== typed.primaryType) throw rpcErrors.invalidParams('Typed data primary type does not match.');
      return evm.signTypedData(typed.domain, types, typed.message);
    }, params?.from),
    // src/adapters/evm.js:45 and ethers base-wallet.js:51-71.
    signTransaction: (transaction, from) => call(evm => evm.signTransaction(transaction), from),
  };
  if (messenger) for (const [name, handler] of Object.entries(actions)) messenger.registerActionHandler(`KeyringController:${name}`, handler);
  return { getAccounts: () => call(evm => [evm.address.toLowerCase()]), ...actions };
}
