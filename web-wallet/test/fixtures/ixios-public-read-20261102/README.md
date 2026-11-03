# Public read availability evidence

`coinstore-recent-trade-denied.json` records one unauthenticated, address-free GET of the exact recent-trade endpoint documented by Coinstore, around 10:04 UTC on 2026-11-02. The request returned HTTP403. Only the exception text was captured; no headers/body were preserved, so the cause cannot be determined. There was no retry, alternate route, credential or proxy substitution. This is availability evidence, not a quote, price fixture or authorization to retry.

Official identity: https://ixios.io/ links https://www.coinstore.com/spot/IXIOSUSDT . API contract: https://coinstore-openapi.github.io/en/index.html (`GET /api/v1/market/trade/{symbol}?size=1`). The quoted currency is USDT, not USD.
