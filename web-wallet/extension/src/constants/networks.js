import { CHAINS, CELLFRAME } from '../../../src/config.js';
import { PQ_NETWORKS } from '../../../src/pq/networks.js';

const mainnet = chain => ({ id: 'mainnet', label: 'Mainnet', endpoint: CHAINS[chain].endpoint, explorer: CHAINS[chain].explorer });
// Approved plan §5.6: list each chain's mainnet and runnable testnets.
// Solana URLs: pinned internal-snaps commit 30d95e6b, packages/solana-wallet-snap/
// src/core/services/config/ConfigProvider.test.ts:26-32 (the test file is the
// only supplied endpoint source). No Solana testnet explorer is in the refs.
// Nile URL: same commit, packages/tron-wallet-snap/.env.example:26,
// TRON_HTTP_BASE_URL_NILE. Explorer base :31; path in src/utils/getExplorerUrl.ts:19-25.
// /opt/dna/tasks/orchestration.md:5921, "[nodus-1] 2026-10-29 — Verifier p8":
// live reads from this host on 2026-10-28 23:12–23:13 UTC supply the full
// genesis hashes below and retract the earlier prefix / last-four-byte rules.
// TRONGRID_BASE_URL hosts nile.api.trongrid.io and shasta.api.trongrid.io,
// plus shasta.trongrid.io, did not resolve (curl exit 6). Shasta is omitted
// because it is not runnable from this host; Nile uses the working HTTP URL.
// Scope strings are labels only: keyring-api 24.1.0 dist/{sol,trx}/constants.cjs:10-12.
export const CHAIN_NETWORKS = {
  // GAP-7: no Nodus mainnet values exist; keep its current module/testnet.
  nodus: [{ id: 'testnet', label: 'Testnet' }],
  ethereum: [mainnet('ethereum')],
  bsc: [mainnet('bsc')],
  solana: [mainnet('solana'),
    { id: 'testnet', label: 'Testnet', endpoint: 'https://api.testnet.solana.com', genesisHash: '4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY', scope: 'solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z' },
    { id: 'devnet', label: 'Devnet', endpoint: 'https://api.devnet.solana.com', genesisHash: 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG', scope: 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1' }],
  tron: [mainnet('tron'),
    { id: 'nile', label: 'Nile', endpoint: 'https://nile.trongrid.io', genesisHash: '0000000000000000d698d4192c56cb6be724a558448e2684802de4d6cd8690dc', scope: 'tron:3448148188', explorer: 'https://nile.tronscan.org/#/transaction/' }],
  cellframe: [{ id: 'mainnet', label: 'Mainnet', endpoint: CELLFRAME.endpoint }],
  ...Object.fromEntries(Object.entries(PQ_NETWORKS).map(([chain, config]) => [chain, config.networks.map(choice => ({ ...choice }))])),
};
export const DEFAULT_NETWORKS = Object.fromEntries(Object.entries(CHAIN_NETWORKS).map(([chain, networks]) => [chain, networks[0].id]));
export function chainNetwork(chain, id = DEFAULT_NETWORKS[chain]) {
  const network = Object.hasOwn(CHAIN_NETWORKS, chain) && CHAIN_NETWORKS[chain].find(network => network.id === id);
  if (!network) throw new Error('Choose a listed network for this chain.');
  return network;
}
