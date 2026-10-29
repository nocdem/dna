import { newPhrase } from '../../../src/keys.js';
import { validateNodusPhrase } from '../../../src/recovery.js';
import { validateNewPassword } from '../../../src/vault.js';
import { AUTO_LOCK_CHOICES } from '../../../src/auto-lock.js';
import { CHAINS, CELLFRAME } from '../../../src/config.js';
import { ASSETS, CPUNK_ASSET, chainBalances, portfolioSnapshot, usdText } from '../../../src/portfolio.js';
import { NODUS_ASSET, nodusNetworkFor } from '../../../src/nodus/network.js';
import { chainNetwork } from '../constants/networks.js';
import { NODUS_PERMISSION } from '../background/permissions.js';
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
  let nodusBalances = null, cpunkBalance = null, nodusHistory = null, nodusPending, historyPending, balanceGeneration = 0;
  let solanaTronBalances = {}, solanaTronHistory = {};
  const solanaTronPending = new Map(), chainGeneration = { solana: 0, tron: 0 };
  const solanaTronHistoryPending = new Map();
  let quotes = {}, pricesAt = null, pricesPending, balanceTimes = {}, referenceKept = {};
  const chainPrefix = chain => {
    if (!['solana', 'tron'].includes(chain)) throw new Error('Unsupported chain.');
    return chain === 'solana' ? 'Solana' : 'Tron';
  };
  const publicState = () => state ? { ...state, evmBalances, nodusBalances, cpunkBalance, nodusHistory, solanaTronBalances, solanaTronHistory } : null;
  async function refresh() {
    const previousNetworks = state?.networks;
    state = await client.request('getState');
    const identity = state.isUnlocked ? JSON.stringify([state.addresses, state.evm, state.nodus]) : null;
    if (identity !== balanceIdentity) {
      evmBalances = {}; nodusBalances = cpunkBalance = nodusHistory = null;
      solanaTronBalances = {}; solanaTronHistory = {}; solanaTronPending.clear(); solanaTronHistoryPending.clear();
      chainGeneration.solana++; chainGeneration.tron++;
      balanceIdentity = identity; balanceGeneration++;
      quotes = {}; pricesAt = null; pricesPending = undefined; balanceTimes = {}; referenceKept = {};
    }
    // Plan §5.6: invalidate only the changed chain, including in-flight reads
    // from a different window's old selection. Other chains retain their data.
    for (const chain of ['solana', 'tron']) if (previousNetworks && previousNetworks[chain] !== state.networks?.[chain]) {
      delete solanaTronBalances[chain]; delete solanaTronHistory[chain];
      delete balanceTimes[chain];
      for (const key of Object.keys(referenceKept)) if (key.startsWith(`${chain}:`)) delete referenceKept[key];
      solanaTronPending.delete(chain); solanaTronHistoryPending.delete(chain); chainGeneration[chain]++;
    }
    return publicState();
  }
  function clearPhrase() { generated = null; phraseStep = null; }
  // src/portfolio-view.js:64-81,118-127: the same public asset registry and
  // snapshot as the web screen. Test-network coins have no USD price identity
  // (operator: Solana/TRON test balances must not enter the dollar total).
  function portfolioDetails() {
    const nodus = nodusNetworkFor(state?.nodus?.state === 'ready', { module: true, tokens: state?.nodus?.tokens });
    const networks = { nodus, ...CHAINS, cellframe: CELLFRAME };
    const assets = [
      { ...NODUS_ASSET, balanceUnavailable: nodus.balanceUnavailable },
      ...nodus.tokens.map(token => ({ ...token, chain: 'nodus', key: `nodus:${token.symbol}` })),
      ...ASSETS.filter(asset => !state?.networks?.[asset.chain] || state.networks[asset.chain] === 'mainnet')
        .concat(ASSETS.filter(asset => state?.networks?.[asset.chain] && state.networks[asset.chain] !== 'mainnet' && asset.symbol === CHAINS[asset.chain].symbol)
          .map(({ priceId, ...asset }) => asset)),
      CPUNK_ASSET,
    ];
    const balances = {};
    for (const chain of Object.keys(networks)) {
      const rows = chain === 'nodus' ? nodusBalances : chain === 'cellframe' ? (cpunkBalance && !cpunkBalance.error ? [{ symbol: 'CPUNK', balance: cpunkBalance.balance }] : cpunkBalance)
        : ['ethereum', 'bsc'].includes(chain) ? evmBalances[chain] : solanaTronBalances[chain];
      if (chain !== 'nodus') networks[chain] = { ...networks[chain], stage: chainNetwork(chain, state?.networks?.[chain]).label };
      if (rows === undefined || rows === null) {
        const pending = chain === 'nodus' || chain === 'cellframe' ? nodusPending : ['ethereum', 'bsc'].includes(chain) ? balancePending : solanaTronPending.has(chain);
        if (pending) for (const asset of assets.filter(asset => asset.chain === chain)) balances[asset.key] = { state: 'loading' };
        continue;
      }
      try {
        const read = chainBalances(chain, rows, balanceTimes[chain], assets); Object.assign(balances, read);
        for (const [key, value] of Object.entries(read)) if (value.state === 'ready') referenceKept[key] = { units: value.units, observedAt: value.observedAt };
      }
      catch { for (const asset of assets.filter(asset => asset.chain === chain)) balances[asset.key] = { state: 'error' }; }
    }
    const readingChains = new Set([
      ...(balancePending ? ['ethereum', 'bsc'] : []), ...(nodusPending ? ['nodus', 'cellframe'] : []), ...solanaTronPending.keys(),
    ]);
    return { networks, snapshot: portfolioSnapshot(balances, quotes, Date.now(), assets, referenceKept), readingChains,
      reading: readingChains.size > 0 || Boolean(pricesPending), updatedAt: Math.max(pricesAt || 0, ...Object.values(balanceTimes)) };
  }
  // Design r3 §2.4a / src/portfolio-view.js:122-127,234-252. Convert each
  // chain independently, so a failed read cannot stop approval/page refresh.
  // Keep these clock-dependent strings out of publicState's redraw comparison.
  function portfolio() {
    const balances = {}, now = Date.now();
    for (const chain of Object.keys(CHAINS)) {
      if (state?.networks?.[chain] && state.networks[chain] !== 'mainnet') continue;
      const rows = ['ethereum', 'bsc'].includes(chain) ? evmBalances[chain] : solanaTronBalances[chain];
      const pending = ['ethereum', 'bsc'].includes(chain) ? balancePending : solanaTronPending.has(chain);
      if (rows === undefined && !pending) continue;
      try {
        if (rows === undefined) Object.assign(balances, Object.fromEntries(ASSETS.filter(asset => asset.chain === chain).map(asset => [asset.key, { state: 'loading' }])));
        else Object.assign(balances, chainBalances(chain, rows, balanceTimes[chain]));
      } catch {
        for (const asset of ASSETS.filter(asset => asset.chain === chain)) balances[asset.key] = { state: 'error' };
      }
    }
    const snap = portfolioSnapshot(balances, quotes, now, ASSETS);
    return {
      label: snap.state === 'partial' ? 'Known value · incomplete' : snap.state === 'loading' ? 'Updating portfolio' : 'Estimated portfolio value',
      total: usdText(snap.total, snap.positive),
      status: snap.state === 'idle' ? 'Refresh all to read your balances and prices.'
        : snap.state === 'loading' ? `${snap.known} of ${ASSETS.length} asset values available. Reading all networks…`
        : snap.complete ? 'All supported asset balances are included.'
        : `${snap.missingBalances} balances and ${snap.missingPrices} prices unavailable or out of date. Missing values are excluded.`,
    };
  }
  async function unlock(password) {
    try { await client.request('submitPasswordOrEncryptionKey', [{ password }]); return await refresh(); }
    finally { password = null; }
  }
  return {
    request: (method, args = []) => client.request(method, args),
    get state() { return publicState(); }, get phraseStep() { return phraseStep; }, refresh, unlock, clearPhrase, portfolio, portfolioDetails,
    async loadPrices({ force = false } = {}) {
      if (!state?.isUnlocked) return;
      if (pricesPending) return pricesPending;
      if (!force && pricesAt !== null && Date.now() - pricesAt < 60_000) return;
      const started = balanceGeneration;
      const request = client.request('getPrices').then(value => {
        if (started !== balanceGeneration || !state?.isUnlocked) return;
        const next = Object.fromEntries(Object.entries(value).map(([key, quote]) => [key, { units: BigInt(quote.units), observedAt: quote.observedAt }]));
        quotes = next; pricesAt = Date.now();
      }).catch(() => {
        // src/portfolio-view.js:271-275: failed reads retain previous quotes;
        // portfolioSnapshot still expires each quote by its own observedAt.
      }).finally(() => { if (pricesPending === request) pricesPending = undefined; });
      pricesPending = request; return request;
    },
    beginCreate() { generated = validateNodusPhrase(generatePhrase()); phraseStep = 'backup'; return generated; },
    beginImport() { clearPhrase(); phraseStep = 'import'; },
    confirmBackup() { if (phraseStep !== 'backup') throw new Error('No recovery backup to confirm.'); phraseStep = 'verify'; },
    async skipVerification(password, confirmation) {
      if (phraseStep !== 'backup' || !generated) throw new Error('No recovery backup to confirm.');
      return this.savePhrase(generated, password, confirmation, { skipVerification: true });
    },
    async savePhrase(phrase, password, confirmation, { skipVerification = false } = {}) {
      let bytes;
      try {
        if (!['verify', 'import'].includes(phraseStep) && !(phraseStep === 'backup' && skipVerification && phrase === generated)) throw new Error('Confirm your recovery backup first.');
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
    async approveNodusConnect(pending) {
      const names = Object.keys(pending.requestData.permissions);
      if (names.length !== 1 || names[0] !== NODUS_PERMISSION) throw new Error('Unsupported connection permissions.');
      await client.request('approvePermissionsRequest', [structuredClone(pending.requestData)]); return refresh();
    },
    async approveNodusMessage(pending) { await client.request('resolvePendingApproval', [pending.id, true]); return refresh(); },
    async rejectNodusMessage(pending) { await client.request('rejectPendingApproval', [pending.id]); return refresh(); },
    async approveEvm(pending) { await client.request('resolvePendingApproval', [pending.id, true]); return refresh(); },
    async rejectEvm(pending) { await client.request('rejectPendingApproval', [pending.id]); return refresh(); },
    async loadEvmBalances({ force = false } = {}) {
      if (!state?.isUnlocked) return;
      if (balancePending) return balancePending;
      if (!force && Object.keys(evmBalances).length) return;
      const started = balanceIdentity;
      balancePending = (async () => {
        const chains = ['ethereum', 'bsc'];
        const times = {};
        const results = await Promise.allSettled(chains.map(chain => client.request('getEvmBalances', [chain]).then(value => { times[chain] = Date.now(); return value; })));
        if (balanceIdentity !== started || !state?.isUnlocked) return;
        evmBalances = Object.fromEntries(results.map((result, index) => [chains[index], result.status === 'fulfilled' ? result.value : { error: result.reason.message }]));
        Object.assign(balanceTimes, times);
        return evmBalances;
      })().finally(() => { balancePending = null; });
      return balancePending;
    },
    prepareEvmSend: fields => client.request('prepareEvmSend', [fields]),
    confirmEvmSend: id => client.request('confirmEvmSend', [id]),
    cancelEvmSend: id => client.request('cancelEvmSend', [id]),
    // Same trusted-port boundary as EVM/Nodus; only public rows/reviews are
    // retained in the UI, and an old unlock's reads cannot replace new state.
    async loadSolanaTronBalances({ force = false, chain: selectedChain } = {}) {
      if (!state?.isUnlocked) return;
      if (selectedChain) chainPrefix(selectedChain);
      const chains = (selectedChain ? [selectedChain] : ['solana', 'tron']).filter(chain => state.addresses?.[chain]);
      return Promise.all(chains.map(chain => {
        if (solanaTronPending.has(chain)) return solanaTronPending.get(chain);
        if (!force && solanaTronBalances[chain]) return;
        const started = chainGeneration[chain];
        const save = value => {
          if (started === chainGeneration[chain] && state?.isUnlocked) {
            solanaTronBalances = { ...solanaTronBalances, [chain]: value }; balanceTimes[chain] = Date.now();
          }
        };
        const request = client.request(`get${chainPrefix(chain)}Balances`).then(save, error => save({ error: error.message }))
          .finally(() => { if (solanaTronPending.get(chain) === request) solanaTronPending.delete(chain); });
        solanaTronPending.set(chain, request); return request;
      }));
    },
    prepareSolanaTronSend: ({ chain, ...fields }) => client.request(`prepare${chainPrefix(chain)}Send`, [fields]),
    confirmSolanaTronSend: (chain, id) => client.request(`confirm${chainPrefix(chain)}Send`, [id]),
    cancelSolanaTronSend: (chain, id) => client.request(`cancel${chainPrefix(chain)}Send`, [id]),
    async loadSolanaTronHistory(chain, { manual = false } = {}) {
      const prefix = chainPrefix(chain);
      if (!state?.isUnlocked) return;
      if (solanaTronHistoryPending.has(chain)) return solanaTronHistoryPending.get(chain);
      const started = chainGeneration[chain];
      const request = client.request(`get${prefix}History`, [{ manual }]).then(history => {
        if (started === chainGeneration[chain] && state?.isUnlocked) solanaTronHistory = { ...solanaTronHistory, [chain]: history };
      }).catch(error => {
        if (started === chainGeneration[chain] && state?.isUnlocked) solanaTronHistory = { ...solanaTronHistory,
          [chain]: { ...solanaTronHistory[chain], error: error.message } };
      }).finally(() => { if (solanaTronHistoryPending.get(chain) === request) solanaTronHistoryPending.delete(chain); });
      solanaTronHistoryPending.set(chain, request); return request;
    },
    async loadNodusBalances({ force = false } = {}) {
      if (!state?.isUnlocked) return;
      if (nodusPending) return nodusPending;
      if (!force && nodusBalances && cpunkBalance) return;
      const started = balanceGeneration;
      const request = Promise.allSettled([client.request('getNodusBalances'), client.request('getCpunkBalance')]).then(results => {
        if (started !== balanceGeneration || !state?.isUnlocked) return;
        const value = result => result.status === 'fulfilled' ? result.value : { error: result.reason.message };
        nodusBalances = value(results[0]); cpunkBalance = value(results[1]);
        if (results[0].status === 'fulfilled') balanceTimes.nodus = Date.now();
        if (results[1].status === 'fulfilled') balanceTimes.cellframe = Date.now();
      }).finally(() => { if (nodusPending === request) nodusPending = null; });
      nodusPending = request; return request;
    },
    async loadNodusHistory() {
      if (!state?.isUnlocked) return;
      if (historyPending) return historyPending;
      const started = balanceGeneration;
      const request = (async () => {
        let history;
        try { history = await client.request('getNodusHistory'); }
        catch (error) {
          const local = await client.request('getNodusLocalHistory').catch(() => []);
          history = { error: error.message, rows: [], local };
        }
        if (started === balanceGeneration && state?.isUnlocked) nodusHistory = history;
      })().finally(() => { if (historyPending === request) historyPending = null; });
      historyPending = request; return request;
    },
    prepareNodusSend: fields => client.request('prepareNodusSend', [fields]),
    readNodusContract: fields => client.request('readNodusContract', [fields]),
    prepareNodusContract: fields => client.request('prepareNodusContract', [fields]),
    confirmNodusSend: id => client.request('confirmNodusSend', [id]),
    cancelNodusSend: id => client.request('cancelNodusSend', [id]),
    discardNodusActivity: () => client.request('discardNodusActivity'),
    resubmitNodusSend: hash => client.request('resubmitNodusSend', [hash]),
    async selectEvmNetwork(chain) { await client.request('selectEvmNetwork', [chain]); return refresh(); },
    async setChainNetwork(chain, network) {
      await client.request('setChainNetwork', [chain, network]); await refresh();
      if (['solana', 'tron'].includes(chain)) await Promise.all([
        this.loadSolanaTronBalances({ chain }), this.loadSolanaTronHistory(chain),
      ]);
      return publicState();
    },
    async setEvmEndpoint(chain, endpoint) { await client.request('setEvmEndpoint', [chain, endpoint]); return refresh(); },
    async revoke(origin) {
      const permissions = state?.subjects?.[origin]?.permissions;
      const names = permissions ? [Caip25EndowmentPermissionName, NODUS_PERMISSION].filter(name => permissions[name]) : [Caip25EndowmentPermissionName];
      await client.request('removePermissionsFor', [{ [origin]: names }]); return refresh();
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
