import { CHAINS } from '../../../src/config.js';

// Ethereum Sepolia and BNB Smart Chain testnet, defined here in the extension and not in the shared src/config.js
// CHAINS table: that table is read by the web wallet and Connect and iterates into their asset lists, so a new
// entry there would add a test asset to both (WALLET SURFACES: fewest shared edits). Each test network has this
// one definition, used by websites (givens item 81, plan 2026-11-08-swap-bot-plan.nodus1.md section 18 change 6)
// and by the wallet's own network selector (approved plan section 5.6: every runnable testnet of a chain).
// Values from the pinned chain list /home/nocdem/refs/ethereum-lists-chains-2b31d670/_data/chains/:
// eip155-11155111.json (Sepolia) and eip155-97.json (BNB Smart Chain testnet): name, chainId, a public RPC
// without an API key, native currency / 18 decimals and an EIP-3091 explorer.
// No token is listed on either: the mainnet token contracts do not exist there and no pinned source gives test
// ones (the swap's test USDT, givens item 77, is named by the site that asks for the payment).
export const SEPOLIA = Object.freeze({
  name: 'Ethereum Sepolia', symbol: 'ETH', decimals: 18, chainId: 11155111,
  endpoint: 'https://ethereum-sepolia-rpc.publicnode.com', explorer: 'https://sepolia.etherscan.io/tx/',
  rpcOptions: Object.freeze([Object.freeze({ url: 'https://ethereum-sepolia-rpc.publicnode.com', label: 'PublicNode' })]),
  tokens: Object.freeze([]), testnet: true,
});
export const BSC_TESTNET = Object.freeze({
  name: 'BNB Smart Chain Testnet', symbol: 'tBNB', decimals: 18, chainId: 97,
  endpoint: 'https://bsc-testnet-rpc.publicnode.com', explorer: 'https://testnet.bscscan.com/tx/',
  rpcOptions: Object.freeze([
    Object.freeze({ url: 'https://bsc-testnet-rpc.publicnode.com', label: 'PublicNode' }),
    Object.freeze({ url: 'https://data-seed-prebsc-1-s1.bnbchain.org:8545', label: 'BNB Chain (data seed)' }),
  ]),
  tokens: Object.freeze([]), testnet: true,
});

// Every network the extension's EVM provider can have selected, by chain key.
export const EVM_NETWORKS = Object.freeze({ ethereum: CHAINS.ethereum, bsc: CHAINS.bsc, sepolia: SEPOLIA, bsctestnet: BSC_TESTNET });
export const EVM_CHAINS = Object.freeze(Object.keys(EVM_NETWORKS));
// The networks the wallet's own screens (balances, send, RPC choice) and the saved endpoint state cover.
export const WALLET_EVM_CHAINS = EVM_CHAINS;
// The two chains of the network selector; each starts on its mainnet (plan section 5.6 d).
export const EVM_FAMILIES = Object.freeze(['ethereum', 'bsc']);
const TEST_KEYS = Object.freeze({ ethereum: 'sepolia', bsc: 'bsctestnet' }), TEST_IDS = Object.freeze({ ethereum: 'sepolia', bsc: 'testnet' });
// A selector choice ('mainnet', 'sepolia' or 'testnet') of a chain -> the chain key above, and back.
export const evmKey = (family, networkId) => (networkId === TEST_IDS[family] ? TEST_KEYS[family] : family);
export const evmFamily = key => (key === 'sepolia' ? 'ethereum' : key === 'bsctestnet' ? 'bsc' : key);
export const evmNetworkId = key => (key === 'sepolia' ? 'sepolia' : key === 'bsctestnet' ? 'testnet' : 'mainnet');
export const isEvmTestKey = key => EVM_NETWORKS[key]?.testnet === true;
// A chain key's receive address: a test network uses its chain's account.
export const evmAddressKey = evmFamily;
