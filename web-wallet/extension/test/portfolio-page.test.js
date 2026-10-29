import test from 'node:test';
import assert from 'node:assert/strict';
import { portfolioReaders } from '../src/ui/wallet-page.js';

// Package A: distinct replies pin every trusted method and its parameters.
// Node >=22, no flags/network/artifacts. Identical replies could falsely pass.
test('portfolio reads every chain through its own trusted background method', async () => {
  const calls = [], ui = { request: async (method, args = []) => { calls.push([method, args]); return method; } };
  const readers = portfolioReaders(ui);
  for (const chain of ['nodus', 'ethereum', 'bsc', 'solana', 'tron', 'cellframe', 'ixios']) {
    const value = await readers.readBalances(chain);
    assert.equal(value[0]?.symbol || value, chain === 'cellframe' ? 'CPUNK' : calls.at(-1)[0]);
  }
  assert.deepEqual(calls, [['getNodusBalances', []], ['getEvmBalances', ['ethereum']], ['getEvmBalances', ['bsc']],
    ['getSolanaBalances', []], ['getTronBalances', []], ['getCpunkBalance', []], ['getIxiosBalance', []]]);
  await assert.rejects(readers.readBalances('invented'), /Unsupported/);
});
