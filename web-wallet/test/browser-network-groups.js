// Parent browser assertions for the mounted wallet. No network, key, or fixture
// implementation is mocked here. Call after restore; requires built-in networks.
// Used by the packaged receive gate and the extension layout suite. The caller
// owns browser cleanup; these checks leave no artifacts and never skip.
import assert from 'node:assert/strict';

// The address book lists only networks with an address check, in selector order:
// no Tidecoin check exists; the Ixios check is extension-only (Ixios sends exist
// only there). src/app.js:776, extension/src/ui/address-book-page.js:63-64.
export async function assertNetworkGroups(page, { ixios = true, cellframe = true, addressBookIxios = false } = {}) {
  const pq = ['nodus', ...(cellframe ? ['cellframe'] : []), ...(ixios ? ['ixios'] : []),
    'algorand', 'tidecoin', 'ckb', 'soqucoin', 'qtc', 'xion', 'splendor', 'asentum'];
  const legacy = ['ethereum', 'bsc', 'solana', 'tron'];
  const expected = [{ id: 'pq', label: 'Post-quantum (PQ)', values: pq },
    { id: 'legacy', label: 'Legacy', values: legacy }];
  const selected = await page.locator('#chain').inputValue();
  assert.deepEqual(await page.locator('#chain optgroup').evaluateAll(groups => groups.map(group => ({
    id: group.dataset.networkGroup, label: group.label, values: [...group.children].map(option => option.value),
  }))), expected);
  assert.equal(await page.locator('#portfolio-filters button').count(), 0);
  assert.equal(await page.locator('#portfolio-filters').isVisible(), false);
  const visibleNetworks = await page.locator('#balances .network-assets').evaluateAll(rows => rows.map(row => row.dataset.chain));
  assert.ok(visibleNetworks.every(chain => [...pq, ...legacy].includes(chain)));
  assert.equal(new Set(visibleNetworks).size, visibleNetworks.length);
  assert.deepEqual(await page.locator('#address-book-network optgroup').evaluateAll(groups => groups.map(group => ({
    id: group.dataset.networkGroup, values: [...group.children].map(option => option.value),
  }))), [{ id: 'pq', values: pq.filter(chain => chain !== 'tidecoin' && (chain !== 'ixios' || addressBookIxios)) }, { id: 'legacy', values: legacy }]);
  assert.equal(await page.locator('#chain').inputValue(), selected);
  assert.equal(await page.locator('#portfolio-networks').isVisible(), false);
  // 0.1.153-0.1.155: the grouped network chips live in the closed network
  // disclosure (src/app.js:2317, extension wallet-screen.js:54), one per network.
  assert.deepEqual(await page.locator('#portfolio-networks .network-health').evaluateAll(chips => chips.map(chip => chip.dataset.chain)), [...pq, ...legacy]);
}
