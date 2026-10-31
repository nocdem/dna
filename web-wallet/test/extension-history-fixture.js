// Test-only fixture writer, bundled into a TEMPORARY copy of the extension.
// Runs only while the actual wallet is locked. Uses the shipped WASM and real
// Connect/store/counter adapter to create an encrypted public fixture without
// starting network connection. Never shipped or loaded by production pages.
import { createConnect } from '../extension/src/background/connect.js';
import { createNodusClient } from '../src/nodus/client.js';
import { createNodusSendModule, NODUS_SEND_NETWORK } from '../src/nodus/send-module.js';
import { nodusSigningSeed } from '../src/nodus/derive.js';
import { parseVault, VAULT_KEY } from '../src/vault.js';

export async function seedHistory({ phrase, fingerprint, address, marker }) {
  const { id } = parseVault((await chrome.storage.local.get(VAULT_KEY))[VAULT_KEY]);
  const client = createNodusClient({ factory: () => createNodusSendModule(NODUS_SEND_NETWORK) });
  const connect = createConnect({ storage: chrome.storage.local });
  try {
    await client.identify({ seed: nodusSigningSeed(phrase), fingerprint });
    await connect.open({ client, phrase, vaultId: id, fresh: false });
    const state = connect.getState();
    if (state.phase !== 'open' || !state.persistent) throw new Error(`Fixture cannot open: ${state.text}`);
    await connect.action(state.epoch, 'vaultKeep', { address, value: { name: marker } });
    return { id, fp: state.ownFp };
  } finally { phrase = null; connect.close(); client.lock(); }
}
