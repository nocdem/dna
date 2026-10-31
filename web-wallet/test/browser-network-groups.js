// Parent browser assertions for the mounted wallet. No network, key, or fixture
// implementation is mocked here. Call after restore; requires built-in networks.
// Used by the packaged receive gate and the extension layout suite. The caller
// owns browser cleanup; these checks leave no artifacts and never skip.
import assert from 'node:assert/strict';

export async function assertNetworkGroups(page, { ixios = true, cellframe = true } = {}) {
  const pq = ['nodus', ...(cellframe ? ['cellframe'] : []), ...(ixios ? ['ixios'] : []),
    'algorand', 'tidecoin', 'ckb', 'soqucoin', 'qtc', 'xion', 'splendor', 'asentum'];
  const legacy = ['ethereum', 'bsc', 'solana', 'tron'];
  const expected = [{ id: 'pq', label: 'Post-quantum (PQ)', values: pq },
    { id: 'legacy', label: 'Legacy', values: legacy }];
  const selected = await page.locator('#chain').inputValue();
  assert.deepEqual(await page.locator('#chain optgroup').evaluateAll(groups => groups.map(group => ({
    id: group.dataset.networkGroup, label: group.label, values: [...group.children].map(option => option.value),
  }))), expected);
  for (const [container, control] of [['#portfolio-networks', '.network-health'], ['#portfolio-filters', '.network-filter']]) {
    assert.deepEqual(await page.locator(container + ' > [data-network-group]').evaluateAll((groups, control) => groups.map(group => ({
      id: group.dataset.networkGroup, label: group.getAttribute('aria-label'),
      values: [...group.querySelectorAll(control)].map(button => button.dataset.chain),
    })), control), expected);
    assert.deepEqual(await page.locator(container + ' .network-group-title').allTextContents(), expected.map(group => group.label));
  }
  assert.equal(await page.locator('#portfolio-filters > .network-filter[data-chain="all"]').count(), 1);
  assert.deepEqual(await page.locator('#address-book-network optgroup').evaluateAll(groups => groups.map(group => ({
    id: group.dataset.networkGroup, values: [...group.children].map(option => option.value),
  }))), [{ id: 'pq', values: ['nodus', ...(cellframe ? ['cellframe'] : [])] }, { id: 'legacy', values: legacy }]);
  assert.equal(await page.locator('#chain').inputValue(), selected);
  assert.equal(await page.locator('.network-health[aria-pressed="true"]').count(), 1);
  assert.equal(await page.locator('.network-health[aria-pressed="true"]').getAttribute('data-chain'), selected);
}
