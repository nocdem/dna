# Ixios account history and send status

## Account history: the network's explorer indexer

`src/pq/ixios/indexer-history.js` reads the account history of the selected Ixios network from the indexer its public
explorer uses (`indexer` in `src/pq/ixios/network.js` `IXIOS_NETWORKS`): `https://ixios-api.ixoflow.io` on the main
network (explorer `ixoflow.io`) and `https://nx-api.ixoflow.io` on the test network (explorer `nx.ixoflow.io`), as each
explorer's `js/config.js` (`ixiosIndexer`) named them on 2026-11-14. One request per read: `GET /v1/address/<address>`,
the first page of that address's transactions. No key or account is needed (public, `access-control-allow-origin: *`).

It is wired through the shared reader (`src/history.js` `readHistory('ixios', …)`, `HISTORY_SOURCES.ixios`) into the
web wallet and Connect Activity (`src/app.js` `loadHistory`, read for the selected Ixios network) and into the
extension (`extension/src/background/ixios.js` `getHistory`), with the same limits as the other networks: after a successful
read, the next one comes at most once per 5 minutes by itself and once per 30 seconds on "Refresh history"; a failed read
is not counted, so the next request reads again (as for the other networks).

**Untrusted data.** An answer that describes another address is refused whole. A row is kept only with a 32-byte hash,
96-hex sender and receiver of which one is this address, a millisecond timestamp, a positive decimal amount read with
18 decimals, and the status `success` (shown as confirmed) or `failed` (shown as failed); the explorer's other statuses
(`pending`, `unknown`; ixoflow.io `js/pages/transaction.js` `STATUS_PRESENTATION`) are left out, because this wallet's
own sends are tracked in its activity. Rows are drawn with `textContent`. The history is provider-reported: not a
light-client inclusion proof, direct transfers only.

**Kept.** In memory for the session; with a saved wallet also encrypted with the other networks' history (decision
`2026-10-02-device-cache-only-when-saved.md`; `src/activity-storage.js` serializeHistory / parseHistory). The web
record keeps the Ixios network id, so a record of the other network is not shown; the extension keeps one record per
network under its own key. Saved rows are checked again when loaded (`src/history.js` checkHistoryRows).

This replaces the bounded block scan of the node (`src/pq/ixios/history.js`, at most 50 recent blocks, about one minute
of the test network), which is removed.

## Send status: the selected node

`src/pq/ixios/observe.js` reads a send's status from the selected network's node: the receipt, the block holding it at
its height, the signed bytes the node holds and their signature, and the tip. Confirmed at 60 blocks (decision
`2026-09-23-ixios-send-mainnet-first.md`: "60 blok derinlik = confirmed"); below that the row says "In a block; N of 60
confirmations" (about one minute on the test network, about 2.6 minutes on the main network at the block times measured
on 2026-11-14). The tip moves while the status is read: the closing reads require the block that holds the transfer to
be the same block at its height and the chain to be no lower than the first tip, and the depth is counted from that
first tip. (Before, any new block during the read failed it with "Ixios tip changed while checking status.", seen live
on the test network on 2026-11-14.)

## Gas price cap

The send form's maximum gas price starts with the protocol minimum for the selected network's checked tip
(`src/pq/ixios/preflight.js` `readIxiosGasCap`, the ixiosSpark v1.1.1 `zeta/zeta.go` floor already used by the
preflight). Both networks quoted exactly that floor on 2026-11-14 (main 93000000000000000 at height 32794185, test
100000000000000000 at 258815). The node's own quote is not used for the cap, so the review still refuses a quote above
it; a user can raise the cap by hand.
