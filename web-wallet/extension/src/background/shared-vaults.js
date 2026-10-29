import { NODUS_REVIEW_MS } from '../../../src/adapters/nodus.js';
import { formatUnits } from '../../../src/core.js';
import { NODUS_ASSET } from '../../../src/nodus/network.js';

// src/vaults/ui.js call inventory (b15901de9): vaultOpen 259/280/703/752,
// vaultCreate 636, vaultBalance 352, vaultCoins 360, vaultHistory 383,
// nameOf 306, nameLookup 615, rulesetInfo 661/728, vaultPropose 811,
// vaultReview 847/922; these read or create an UNSIGNED request/descriptor.
// vaultApprove 843 signs; vaultSubmit 985 combines approvals and broadcasts.
// The latter two require a reviewed id. No page receives a signed envelope.
export const SHARED_READS = Object.freeze(['vaultOpen', 'vaultCreate', 'vaultBalance', 'vaultCoins', 'vaultHistory',
  'nameOf', 'nameLookup', 'rulesetInfo', 'vaultPropose', 'vaultReview']);
export function createSharedVaults({ active }) {
  let nextId = 0; const reviews = new Map();
  const same = (session, client) => { if (active() !== session || session.client !== client || client.state !== 'ready') throw new Error('Nodus connection changed. Review the payment again.'); };
  return {
    lock() { reviews.clear(); },
    async read(method, fields) {
      if (!SHARED_READS.includes(method)) throw new Error('Unsupported shared-vault read.');
      const session = active(), client = session.client, value = await client[method](fields);
      same(session, client); return value;
    },
    async prepare(method, fields) {
      if (!['vaultApprove', 'vaultSubmit'].includes(method)) throw new Error('Unsupported shared-vault action.');
      const session = active(), client = session.client, args = structuredClone(fields);
      const decoded = await client.vaultReview(args); same(session, client);
      if (decoded.digest !== args.digest) throw new Error('This payment request changed after it was shown. Nothing was signed.');
      // src/vaults/ui.js:1251-1270: decoded outputs, fee, expiry, checked inputs.
      const rows = decoded.outputs.flatMap(output => [[output.change ? 'Change back to this vault' : 'Pay to', output.owner], ['Amount', `${formatUnits(output.amount, NODUS_ASSET.decimals)} NODUS`]]);
      rows.push(['Network fee', `${formatUnits(decoded.fee, NODUS_ASSET.decimals)} NODUS`], ['Valid until', `Block ${decoded.expiryHeight}`], ['Coins checked', `All ${decoded.inputs.length} coins it spends belong to this vault.`]);
      const id = String(++nextId), expiresAt = Date.now() + NODUS_REVIEW_MS;
      reviews.set(id, { method, args, session, client, expiresAt }); return { id, expiresAt, review: rows };
    },
    async confirm(id) {
      const review = reviews.get(id); if (!review) throw new Error('This review is already closed.'); reviews.delete(id);
      same(review.session, review.client);
      if (Date.now() >= review.expiresAt) throw new Error('Review expired. Prepare the payment again.');
      const result = await review.client[review.method](review.args); same(review.session, review.client); return result;
    },
    cancel(id) { reviews.delete(id); },
  };
}
