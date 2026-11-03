import { BaseController } from '@metamask/base-controller';
import { CHAIN_NETWORKS, DEFAULT_NETWORKS, chainNetwork } from '../constants/networks.js';

// Plan §5.6: one persistent selection per chain; the existing EVM active
// chain and wallet_switchEthereumChain behaviour remain in evm.js.
export function createNetworks({ messenger, store, onChanged }) {
  const metadata = { selected: { persist: true } };
  const saved = store.getInitialState('NetworksController', metadata).selected;
  const selected = Object.fromEntries(Object.entries(CHAIN_NETWORKS).map(([chain, choices]) => [chain,
    choices.some(network => network.id === saved?.[chain]) ? saved[chain] : DEFAULT_NETWORKS[chain]]));
  const controller = new BaseController({ name: 'NetworksController', metadata,
    messenger: messenger.buildChild({ namespace: 'NetworksController' }), state: { selected } });
  return { controller, getState: () => structuredClone(controller.state.selected),
    get: chain => chainNetwork(chain, controller.state.selected[chain]),
    async select(chain, id) {
      if (typeof id !== 'string') throw new Error('Choose a listed network for this chain.');
      chainNetwork(chain, id);
      if (controller.state.selected[chain] === id) return;
      // Close reviews/read jobs synchronously before publishing the new choice.
      onChanged(chain);
      controller.update(state => { state.selected[chain] = id; });
      await store.flush();
    },
    // Every opening starts each chain on its listed default — mainnet where one
    // exists (operator 2026-11-03: "hersey varsa yeniden acista mainnet",
    // "2 hepsi": PQ networks and the Solana / TRON setting alike).
    async resetToDefaults() {
      const changed = Object.keys(DEFAULT_NETWORKS).filter(chain => controller.state.selected[chain] !== DEFAULT_NETWORKS[chain]);
      if (!changed.length) return;
      for (const chain of changed) onChanged(chain);
      controller.update(state => { for (const chain of changed) state.selected[chain] = DEFAULT_NETWORKS[chain]; });
      await store.flush();
    },
  };
}
