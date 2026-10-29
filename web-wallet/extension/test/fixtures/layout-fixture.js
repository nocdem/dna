import { mountWalletPage } from '../../src/ui/app.js';
import { ASSETS } from '../../../src/portfolio.js';
import { CHAINS } from '../../../src/config.js';
import { DEFAULT_NETWORKS } from '../../src/constants/networks.js';
import { NODUS_PERMISSION, NODUS_ACCOUNT_CAVEAT } from '../../src/background/permissions.js';
import { Caip25EndowmentPermissionName, getCaip25PermissionFromLegacyPermissions, setEthAccounts } from '@metamask/chain-agnostic-permission';

// Public, deliberately non-signing fixtures. All observed times come from the
// page's clock when the fake answers; no calendar date can expire this fixture.
const query = new URLSearchParams(location.search), stage = query.get('stage') || 'home';
document.body.dataset.page = query.get('page') || 'popup';
const addresses = { nodus: 'ab'.repeat(64), ethereum: '0x' + '12'.repeat(20), bsc: '0x' + '12'.repeat(20),
  solana: '1'.repeat(44), tron: 'T' + '1'.repeat(33), cpunk: 'R'.repeat(104) };
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
if (stage === 'connect') state.pendingApprovals.connect = { id: 'connect', origin: 'https://connect-request.example', requestData: { origin: 'https://connect-request.example', permissions: getCaip25PermissionFromLegacyPermissions() } };
if (stage === 'signature') state.pendingApprovals.signature = signature('signature', 'Full Nodus message <img src=x onerror=alert(1)> ' + 'ab'.repeat(100));
if (stage === 'approvals') state.pendingApprovals = {
  first: signature('first', 'First queued message'), second: signature('second', 'Second queued message'),
};
const calls = [], balanceTimes = {};
let quotes = {};
const client = { onNotification: () => () => {}, onDisconnect: () => () => {}, close() {}, async request(method, params = []) {
  calls.push({ method, params: structuredClone(params) });
  if (method === 'getState') return structuredClone({ ...state, addresses: state.isUnlocked ? addresses : {} });
  if (['messengerSubscribe', 'messengerUnsubscribe', 'setLastActiveTime'].includes(method)) return;
  if (method === 'submitPasswordOrEncryptionKey') { state.isUnlocked = true; return; }
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
  if (method === 'getNodusHistory') return { status: 'Fixture account history', local: [
    { amount: '1', symbol: 'NODUS', status: 'submitted', note: 'Awaiting confirmation.', hash: 'ab'.repeat(32) },
  ], rows: [{ title: 'Received NODUS', sign: '+', amount: '2', detail: 'Public fixture transfer', height: 12, wire: 'cd'.repeat(32) }] };
  if (method === 'getSolanaHistory' || method === 'getTronHistory') return { network: 'mainnet', status: 'Fixture account history', local: [], rows: [] };
  if (method === 'prepareEvmSend') return { id: 'layout-review', ...params[0], fee: 'Up to 0.001 ETH' };
  if (method === 'cancelEvmSend') return;
  if (method === 'resolvePendingApproval' || method === 'rejectPendingApproval') { delete state.pendingApprovals[params[0]]; return; }
  if (method === 'approvePermissionsRequest') { delete state.pendingApprovals[params[0].id]; return; }
  if (method === 'removePermissionsFor') { for (const origin of Object.keys(params[0])) delete state.subjects[origin]; return; }
  if (method === 'setChainNetwork') { state.networks[params[0]] = params[1]; return; }
  if (method === 'setPreference') { state.preferences[params[0]] = params[1]; return true; }
  throw new Error(`Unexpected layout fixture method: ${method}`);
} };
const mounted = await mountWalletPage({ document, window, client });
window.layout = { calls, state, balances, balanceTimes, get quotes() { return quotes; }, refresh: mounted.refresh, dispose: mounted.dispose };
