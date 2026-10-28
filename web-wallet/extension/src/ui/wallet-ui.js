import { newPhrase } from '../../../src/keys.js';
import { validateNodusPhrase } from '../../../src/recovery.js';
import { validateNewPassword } from '../../../src/vault.js';
import { AUTO_LOCK_CHOICES } from '../../../src/auto-lock.js';
import { CHAINS } from '../../../src/config.js';
import { Caip25CaveatType, Caip25EndowmentPermissionName, getPermittedEthChainIds,
  setEthAccounts, setPermittedEthChainIds } from '@metamask/chain-agnostic-permission';

// Port: permissions-connect.tsx:144-148, 668-701. Package 4a supports EVM scopes only.
export function connectDetails(pending) {
  const request = pending?.requestData, permission = request?.permissions?.[Caip25EndowmentPermissionName];
  const caveat = permission?.caveats?.find(item => item.type === Caip25CaveatType);
  if (!caveat || Object.keys(request.permissions).some(key => key !== Caip25EndowmentPermissionName)) throw new Error('Unsupported connection permissions.');
  const requested = getPermittedEthChainIds(caveat.value);
  const networks = ['ethereum', 'bsc'].map(key => ({ key, name: CHAINS[key].name, chainId: `0x${CHAINS[key].chainId.toString(16)}` }));
  if (requested.some(id => !networks.some(network => network.chainId === id)) ||
    [...Object.keys(caveat.value.requiredScopes), ...Object.keys(caveat.value.optionalScopes)].some(scope => scope !== 'wallet:eip155' && !scope.startsWith('eip155:'))) {
    throw new Error('Unsupported connection networks.');
  }
  return { request, caveat, networks: requested.length ? networks.filter(network => requested.includes(network.chainId)) : networks };
}

export function createWalletUi(client, { generatePhrase = newPhrase } = {}) {
  let state = null, generated = null, phraseStep = null;
  let evmBalances = {}, balanceIdentity, balancePending;
  const publicState = () => state ? { ...state, evmBalances } : null;
  async function refresh() {
    state = await client.request('getState');
    const identity = state.isUnlocked ? JSON.stringify([state.addresses, state.evm]) : null;
    if (identity !== balanceIdentity) { evmBalances = {}; balanceIdentity = identity; }
    return publicState();
  }
  function clearPhrase() { generated = null; phraseStep = null; }
  async function unlock(password) {
    try { await client.request('submitPasswordOrEncryptionKey', [{ password }]); return await refresh(); }
    finally { password = null; }
  }
  return {
    get state() { return publicState(); }, get phraseStep() { return phraseStep; }, refresh, unlock, clearPhrase,
    beginCreate() { generated = validateNodusPhrase(generatePhrase()); phraseStep = 'backup'; return generated; },
    beginImport() { clearPhrase(); phraseStep = 'import'; },
    confirmBackup() { if (phraseStep !== 'backup') throw new Error('No recovery backup to confirm.'); phraseStep = 'verify'; },
    async savePhrase(phrase, password, confirmation) {
      let bytes;
      try {
        if (!['verify', 'import'].includes(phraseStep)) throw new Error('Confirm your recovery backup first.');
        phrase = validateNodusPhrase(phrase); validateNewPassword(password);
        if (password !== confirmation) throw new Error('Passwords do not match.');
        if (phraseStep === 'verify' && phrase !== generated) throw new Error('The phrase does not match. Re-enter your saved backup.');
        // Reference legacy-background-api-service.ts:4449-4459 accepts UTF-8 bytes.
        bytes = [...new TextEncoder().encode(phrase)];
        await client.request('createNewVaultAndRestore', [password, bytes]);
        clearPhrase();
        return await unlock(password);
      } finally { bytes?.fill(0); phrase = null; password = null; confirmation = null; }
    },
    async lock() { clearPhrase(); await client.request('setLocked'); return refresh(); },
    async approveConnect(pending, accounts, chainIds) {
      const { networks } = connectDetails(pending);
      if (!accounts.length || !chainIds.length || chainIds.some(id => !networks.some(network => network.chainId === id))) throw new Error('Select an account and networks to permit.');
      const approved = structuredClone(pending.requestData);
      const caveat = approved.permissions[Caip25EndowmentPermissionName].caveats.find(item => item.type === Caip25CaveatType);
      caveat.value = setEthAccounts(setPermittedEthChainIds(caveat.value, chainIds), accounts);
      await client.request('approvePermissionsRequest', [approved]); return refresh();
    },
    async rejectConnect(pending) { await client.request('rejectPermissionsRequest', [pending.id]); return refresh(); },
    async approveEvm(pending) { await client.request('resolvePendingApproval', [pending.id, true]); return refresh(); },
    async rejectEvm(pending) { await client.request('rejectPendingApproval', [pending.id]); return refresh(); },
    async loadEvmBalances({ force = false } = {}) {
      if (!state?.isUnlocked) return;
      if (balancePending) return balancePending;
      if (!force && Object.keys(evmBalances).length) return;
      const started = balanceIdentity;
      balancePending = (async () => {
        const chains = ['ethereum', 'bsc'];
        const results = await Promise.allSettled(chains.map(chain => client.request('getEvmBalances', [chain])));
        if (balanceIdentity !== started || !state?.isUnlocked) return;
        evmBalances = Object.fromEntries(results.map((result, index) => [chains[index], result.status === 'fulfilled' ? result.value : { error: result.reason.message }]));
        return evmBalances;
      })().finally(() => { balancePending = null; });
      return balancePending;
    },
    prepareEvmSend: fields => client.request('prepareEvmSend', [fields]),
    confirmEvmSend: id => client.request('confirmEvmSend', [id]),
    cancelEvmSend: id => client.request('cancelEvmSend', [id]),
    async selectEvmNetwork(chain) { await client.request('selectEvmNetwork', [chain]); return refresh(); },
    async setEvmEndpoint(chain, endpoint) { await client.request('setEvmEndpoint', [chain, endpoint]); return refresh(); },
    async revoke(origin) {
      await client.request('removePermissionsFor', [{ [origin]: [Caip25EndowmentPermissionName] }]); return refresh();
    },
    async setAutoLock(minutes) {
      if (!AUTO_LOCK_CHOICES.includes(minutes)) throw new Error('Invalid auto-lock choice.');
      if (!await client.request('setPreference', ['autoLockTimeLimit', minutes])) throw new Error('The auto-lock choice could not be saved.');
      return refresh();
    },
    async revealPhrase(password) {
      let bytes, decoded;
      try {
        bytes = await client.request('getSeedPhrase', [password]); decoded = Uint8Array.from(bytes);
        return validateNodusPhrase(new TextDecoder().decode(decoded));
      } finally { decoded?.fill(0); bytes?.fill(0); password = null; }
    },
  };
}

// Approved plan §3.5:422-435: the alarm belongs to the background, including after every interface closes.
export function extensionAutoLockNote(minutes) {
  return minutes === 0 ? 'Auto-lock is off. Lock the wallet when you finish. Closing a wallet window does not lock it. Recovery words clear after 10 minutes without use.'
    : `The wallet locks after ${minutes === 60 ? '1 hour' : `${minutes} minutes`} without use in a wallet window, even when all wallet windows are closed. Recovery words clear after 10 minutes without use.`;
}
