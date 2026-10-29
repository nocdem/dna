// Optional standalone entry; the same checks run in ui-flows/ui-render.test.js.
import { withPortfolioPage, checkPortfolioFlows, checkPortfolioStatus } from './fixtures/portfolio-page-checks.js';
await withPortfolioPage(async (page, origin) => {
  await checkPortfolioFlows(page, origin);
  await checkPortfolioStatus(page, origin);
});
