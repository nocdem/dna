// src/app.js:1327-1351,1628-1650. The faucet is deliberately absent on the
// operator's 2026-10-29 instruction. Only the allocation action is mounted.
export function mountClaimAction({ ui, portfolio, run, showReview }) {
  let generation = 0, identity, settledMark, disposed = false;
  async function refresh() {
    const check = ++generation; portfolio.setAction('nodus', undefined);
    if (!ui.state.nodus?.claimable) return;
    const current = () => !disposed && check === generation;
    try {
      const status = await ui.request('getClaimStatus'); if (!current() || !status.claimable) return;
      const [whole, fraction] = status.amountText.replace(/ NODUS$/, '').split('.');
      const amount = whole.replace(/\B(?=(\d{3})+(?!\d))/g, ',') + (fraction ? `.${fraction}` : '');
      portfolio.setAction('nodus', { label: `Claim your allocation (${amount} NODUS)`,
        note: `An allocation of ${amount} NODUS is waiting for this wallet. Claiming it adds it to your NODUS balance.`,
        run: () => run(async () => {
          const review = await ui.request('prepareClaim');
          if (!current()) { await ui.cancelNodusSend(review.id); return; }
          showReview(review, { chain: 'nodus', title: 'Review claim' });
        }) });
    } catch (error) {
      if (current()) portfolio.setAction('nodus', { label: 'Check for a NODUS allocation again',
        note: `Could not check whether an allocation is waiting for this wallet: ${error.message || 'unknown error'}`, run: refresh });
    }
  }
  return { refresh, update() {
    const key = `${ui.state.addresses.nodus}:${ui.state.nodus?.state}:${ui.state.nodus?.claimable}`, settled = ui.state.nodusSettled?.claim;
    if (key !== identity) { identity = key; settledMark = settled; void refresh(); }
    // A claim of this wallet reached a final state while this screen stayed open (src/app.js:660-667): read the claim status once.
    else if (settled !== settledMark) { settledMark = settled; void refresh(); }
  },
    dispose() { disposed = true; generation++; } };
}
