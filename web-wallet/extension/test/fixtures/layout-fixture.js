import { mountReferencePage } from '../../src/ui/reference-entry.js';
import { ASSETS } from '../../../src/portfolio.js';
import { CHAINS } from '../../../src/config.js';
import { DEFAULT_NETWORKS } from '../../src/constants/networks.js';
import { NODUS_PERMISSION, NODUS_ACCOUNT_CAVEAT } from '../../src/background/permissions.js';
import { Caip25EndowmentPermissionName, getCaip25PermissionFromLegacyPermissions, setEthAccounts } from '@metamask/chain-agnostic-permission';

// Public, deliberately non-signing fixtures. All observed times come from the
// page's clock when the fake answers; no calendar date can expire this fixture.
const query = new URLSearchParams(location.search), stage = query.get('stage') || 'home';
// Geometry scenarios use manual refresh; the automatic choices are exercised
// by portfolio-page.browser.js. This is an explicit fixture device setting.
localStorage.setItem('nodus.balanceRefreshMinutes', '0');
document.body.dataset.page = query.get('page') || 'popup';
const addresses = { nodus: 'ab'.repeat(64), ethereum: '0x' + '12'.repeat(20), bsc: '0x' + '12'.repeat(20),
  solana: '1'.repeat(44), tron: 'T' + '1'.repeat(33), cpunk: 'R'.repeat(104), ixios: '0x' + '11'.repeat(48) };
const balances = Object.fromEntries(Object.keys(CHAINS).map(chain => [chain, ASSETS.filter(asset => asset.chain === chain)
  .map((asset, index) => ({ symbol: asset.symbol, balance: String(index + 1) }))]));
const permissions = getCaip25PermissionFromLegacyPermissions();
permissions[Caip25EndowmentPermissionName].caveats[0].value = setEthAccounts(permissions[Caip25EndowmentPermissionName].caveats[0].value, [addresses.ethereum]);
const signature = (id, text) => ({ id, type: 'nodus_signMessage', origin: `https://${id}.example`,
  requestData: { account: addresses.nodus, text, data: text } });
const state = { isInitialized: stage !== 'welcome', isUnlocked: !['welcome', 'unlock'].includes(stage),
  addresses, accounts: [addresses.ethereum], preferences: { autoLockTimeLimit: 0 }, networks: { ...DEFAULT_NETWORKS },
  evm: { selectedChain: 'ethereum', endpoints: { ethereum: CHAINS.ethereum.endpoint, bsc: CHAINS.bsc.endpoint } },
  nodus: { state: 'ready', tokens: [], evmReadable: true, evmBuildable: true, publicKey: '0x' + 'ab'.repeat(2592) },
  pendingApprovals: {}, subjects: {
    'https://evm-site.example': { permissions },
    'https://nodus-site.example': { permissions: { [NODUS_PERMISSION]: { caveats: [{ type: NODUS_ACCOUNT_CAVEAT, value: { address: addresses.nodus } }] } } },
  } };
if (query.has('name')) Object.assign(state.nodus, { nameable: true, registrable: true });
if (stage === 'connect') state.pendingApprovals.connect = { id: 'connect', origin: 'https://connect-request.example', requestData: { origin: 'https://connect-request.example', permissions: getCaip25PermissionFromLegacyPermissions() } };
if (stage === 'signature') state.pendingApprovals.signature = signature('signature', 'Full Nodus message <img src=x onerror=alert(1)> ' + 'ab'.repeat(100));
if (stage === 'approvals') state.pendingApprovals = {
  first: signature('first', 'First queued message'), second: signature('second', 'Second queued message'),
};
const calls = [], balanceTimes = {};
// Hold the initial reads until the geometry test explicitly releases them.
// This observes the actual shared renderer's loading-to-settled transition.
let releaseReads;
const heldReads = query.has('hold') ? new Promise(resolve => { releaseReads = resolve; }) : null;
let quotes = {};
const client = { onNotification: () => () => {}, onDisconnect: () => () => {}, close() {}, async request(method, params = []) {
  calls.push({ method, params: structuredClone(params) });
  if (heldReads && /^(?:get(?:Nodus|Evm|Solana|Tron)Balances|getCpunkBalance|getIxiosBalance|getPrices)$/u.test(method)) await heldReads;
  if (method === 'getState') return structuredClone({ ...state, addresses: state.isUnlocked ? addresses : {} });
  if (['messengerSubscribe', 'messengerUnsubscribe', 'setLastActiveTime'].includes(method)) return;
  if (['keepBalances', 'checkNodusLiveness'].includes(method)) return;
  if (method === 'getKeptBalances') return {};
  if (method === 'getAddressBook') return { entries: [] };
  if (method === 'getSessionLog') return { entries: [], running: [] };
  if (method === 'getOwnName') return query.get('name') === 'none' ? { found: false } : { found: true, name: query.get('name') };
  if (method === 'getNamePrices') return { text: 'public fixture prices' };
  if (method === 'contractAccount') return { balanceWei: '0', nonce: '0', height: '1', pending: false };
  if (method === 'submitPasswordOrEncryptionKey') { state.isUnlocked = true; return; }
  if (method === 'getSeedPhrase') return [...new TextEncoder().encode('abandon '.repeat(23) + 'art')];
  if (method === 'setLocked') { state.isUnlocked = false; return; }
  if (method === 'getPrices') {
    quotes = Object.fromEntries(ASSETS.map((asset, index) => [asset.key, { units: String((index + 1) * 100000000), observedAt: Date.now() }]));
    return structuredClone(quotes);
  }
  const chain = method === 'getEvmBalances' ? params[0] : method === 'getSolanaBalances' ? 'solana' : method === 'getTronBalances' ? 'tron' : undefined;
  if (chain) {
    balanceTimes[chain] = Date.now();
    if (chain === query.get('failed')) throw new Error(`${chain} fixture unavailable`);
    return structuredClone(balances[chain]);
  }
  if (method === 'getNodusBalances') return [{ symbol: 'NODUS', balance: '12.34' }];
  if (method === 'getCpunkBalance') return { balance: '0.75' };
  if (method === 'getIxiosBalance') return [{ symbol: 'IXIOS', balance: '1' }];
  if (method === 'getNodusHistory') return { status: 'Fixture account history', local: [
    { amount: '1', symbol: 'NODUS', status: 'submitted', note: 'Awaiting confirmation.', hash: 'ab'.repeat(32), canResubmit: true },
  ], rows: [{ title: 'Received NODUS', dir: 'in', sign: '+', amount: '2', detail: 'Public fixture transfer', height: 12, time: 1700000000000, wire: 'cd'.repeat(64) },
    { title: 'Witness update', dir: '', sign: '', amount: '', detail: '', height: 11, time: null, wire: '' }] };
  if (['getSolanaHistory', 'getTronHistory', 'getChainHistory'].includes(method)) {
    const chain = method === 'getSolanaHistory' ? 'solana' : method === 'getTronHistory' ? 'tron' : params[0];
    const hash = chain === 'solana' ? '2'.repeat(88) : 'cd'.repeat(32);
    return { network: 'mainnet', status: 'Fixture account history', local: [
      { amount: '1', symbol: CHAINS[chain]?.symbol ?? 'CPUNK', status: 'submitted', note: 'Awaiting confirmation.', hash: chain === 'solana' ? '3'.repeat(88) : 'ab'.repeat(32), to: addresses[chain === 'cellframe' ? 'cpunk' : chain], createdAt: '2026-10-28T00:00:00Z' },
    ], rows: [
      { chain, hash, dir: 'in', amount: '1234567.123456789', symbol: CHAINS[chain]?.symbol ?? 'CPUNK', peer: addresses[chain === 'cellframe' ? 'cpunk' : chain], status: 'confirmed', time: 1700000000000 },
    ] };
  }
  if (method === 'prepareEvmSend') return { id: 'layout-review', ...params[0], fee: 'Up to 0.001 ETH', expiresAt: Date.now() + 60000,
    review: [['Network', 'Ethereum mainnet'], ['From', addresses.ethereum], ['To', params[0].to], ['Asset', params[0].symbol], ['Amount', params[0].amount], ['Network fee', 'Up to 0.001 ETH'], ['Transaction number (nonce)', 7]] };
  if (method === 'confirmEvmSend') return 'public-fixture-transaction';
  if (method === 'cancelEvmSend') return;
  if (method === 'resolvePendingApproval' || method === 'rejectPendingApproval') { delete state.pendingApprovals[params[0]]; return; }
  if (method === 'approvePermissionsRequest') { delete state.pendingApprovals[params[0].id]; return; }
  if (method === 'removePermissionsFor') { for (const origin of Object.keys(params[0])) delete state.subjects[origin]; return; }
  if (method === 'setChainNetwork') {
    if(state.failNetworkWrites==='before')throw new Error('Public fixture network persistence failure');
    state.networks[params[0]] = params[1];
    if(state.failNetworkWrites==='after')throw new Error('Public fixture network persistence failure');
    return;
  }
  if (method === 'setPreference') { state.preferences[params[0]] = params[1]; return true; }
  throw new Error(`Unexpected layout fixture method: ${method}`);
} };
const mounted = await mountReferencePage({ document, window, client });
window.layout = { calls, state, balances, balanceTimes, get quotes() { return quotes; }, releaseReads, refresh: mounted.refresh, dispose: mounted.dispose };
