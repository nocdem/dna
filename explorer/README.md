# DNAC Explorer (`dna-explorerd`)

Read-only block/transaction indexer + JSON API for Nodus Scan. Polls the
Nodus witness cluster over the client SDK, mirrors committed version-3
(cometbft) blocks into a local sqlite index, and serves it over a small HTTP
JSON API. The Nodus Scan frontend (`scan.nodusnetwork.io`) lives in
`website/scan/` (see `website/deploy/README.md`); the legacy
`scan.cpunk.io` frontend is no longer in this repository.

**Version 0.2.2** adds actual payout amounts, recipient pages and address
reward history through an optional read-only local Nodus database. It
does not rebuild the explorer index or change the node's owner-gated RPC.

**Stake releases** — the validator bonds and delegations the chain returns at
an epoch boundary — are read from the same source: `/api/releases/<height>`
and a separate `releases` list on `/api/rewards/<fp>`. A release is returned
stake, not a reward: no payday total or `paid_total` includes it. Same
snapshot, coverage and budget rules as the payout views; no index rebuild,
no node change.

Design: `docs/plans/2026-09-28-scan-v3-design.md` (items 4-5) and the
decision `docs/plans/decisions/2026-09-28-scan-v3-query.md` (both
local-only, not committed — see `feedback_plans_dir_local_only`). The v1
design (`docs/plans/2026-07-21-dnac-explorer-design.md`) describes the
ledger-sequence indexer this version replaces.

**Version 0.2.0 rebuilds its index.** The index schema is now v2. On the
first start of this version the daemon finds no `schema_version = 2` in the
index file, drops every explorer table (the v1 `blocks`/`txs`/`tx_io`/
`addr_stats`/`meta`) and re-indexes the chain from height 1. The index is
derived data; nothing is lost that the chain does not hold. The node the
explorer reads from must answer `dnac_v3_block` and the `dnac_supply`
`chain_id32`/`tip` keys (Nodus with the scan-v3 query) — deploy the nodes
first, then the explorer.

## Component overview

- `src/exp_chain.{c,h}` — read-only wrapper around the Nodus client SDK
  (`nodus/include/nodus/nodus.h`). Owns an ephemeral Dilithium5 identity
  (generated at open, never persisted), rotates across the configured
  witness server list on failure. Four queries:
  `exp_chain_tip` (one observation: `dnac_supply` figures + the 32-byte
  `chain_id32` + the committed `tip` height + the supply buckets — four
  round trips on one connection, all redone on the next server if any
  fails; a node that answers no `chain_id32`/`tip` is not a version-3 node
  and is a failure, never a tip of 0; a node that answers no buckets is an
  older node and is NOT a failure — the buckets show as `null`),
  `exp_chain_v3_page` (one `dnac_v3_block` page),
  `exp_chain_balance` (one address's `dnac_balance`, trying every server) and
  `exp_chain_active_stake` (the active validators' stake for the APY
  estimate: `dnac_validator_list_query` with status 0 = ACTIVE, paged by
  offset, at most 64 pages of 128, summing `self_stake +
  external_delegated` — the stake voting power is built from,
  `dnac/include/dnac/validator.h`; one attempt on the current connection,
  no rotation).
  Also hosts the F4 chain-reset FSM (`exp_reset_fsm_feed`) that gates
  destructive index wipes behind multi-witness, multi-poll confirmation.
- `src/exp_sync.{c,h}` — the sync loop (below). Reads the chain through an
  `exp_sync_source_t` (production: an `exp_chain_t`; tests: fakes).
- `src/exp_extract.{c,h}` — copies one decoded `dnac_v3_block` page into
  index rows and checks that consecutive pages form one block (same header,
  contiguous item indices). It deserializes nothing: the node decodes every
  item with its own runtime decoders and answers the effects already
  derived.
- `src/exp_db.{c,h}` — sqlite index schema v2, the one-transaction height
  write, prepared-statement queries, and `exp_db_verify_index`
  (`--verify-index`).
- `src/exp_http.{c,h}` — the JSON HTTP API (`exp_http_serve`), bound to
  `127.0.0.1` only. Answers from the index, except `/api/address`'s
  balance, which it reads from the node through its own chain handle and
  a 5 s cache (`exp_balance_chain_*`; see "Balance" below), and the
  optional rewards endpoints below.
- `src/exp_rewards.{c,h}` — request-scoped, read-only SQLite snapshots of
  recorded payout and stake-release rows and current accrual from a
  co-located Nodus DB.
  Matches the indexed anchor block, validates coverage and rows, and
  bounds work with a deterministic SQLite VM-operation budget.
- `src/exp_json.{c,h}` — minimal JSON emission helpers (money fields as
  decimal strings — see below).
- `src/main.c` — CLI entry point / daemon lifecycle.
- `tests/` — unit tests, run from the messenger build tree (see Build).
- `deploy/dna-explorerd.service` — systemd unit (sample).
- `deploy/scan.cpunk.io.nginx.conf` — nginx reverse-proxy + static-site
  config (sample).

## Sync (version-3 chain)

One tick every `EXP_SYNC_POLL_SECONDS` (30 s):

1. **Observe** — `exp_chain_tip` returns `chain_id32` and the committed tip
   height. `chain_id32` is fed to the F4 reset FSM (keyed on the 32-byte
   version-3 chain id, stored in index meta as `chain_id32`; the legacy
   `dnac_supply` `chain_id` key is never read). A mismatching chain id seen
   from one server is PENDING (rotate, index nothing); seen from two
   distinct servers over two polls it is CONFIRMED: the index file is
   renamed to `<db>.stale-<hex8>` and a fresh one is opened. Only a
   matching observation's tip and supply figures reach meta (`/api/stats`).
   A matching observation is followed by the active-stake read
   (`exp_chain_active_stake`, same server); its result is stored as the
   `active_stake` meta blob stamped with the observation's tip, and a
   failed read stores "unknown" (the APY estimate is then `null`) — it
   never stops the height walk.
2. **Walk heights** `last_indexed_height + 1 .. tip`, at most 256 per tick
   (a tick that stops at that bound is followed immediately by the next,
   without the poll sleep). Per height: every `dnac_v3_block` page is
   fetched (from item 0, then the node's `nx` until it names none), each
   page must carry the same header as the first and continue the item
   indices; then the block, its items (applied **and** refused), their
   consumed/created coins, their SYSTEM records and the watermark
   `last_indexed_height = height` are written in **one** sqlite
   transaction.
3. **Failure** anywhere in a height (a page fetch, a page from a different
   block after a server rotate, the write) leaves the watermark where it
   was and ends the tick; the next tick retries that height from its first
   page. Heights are written strictly in order — the write refuses any
   height other than `last_indexed_height + 1`.

The sync thread and the HTTP thread share one sqlite connection
(`SQLITE_OPEN_FULLMUTEX`); the sync thread holds the shared `db_lock` as a
writer around each height's write (and around a reset's close/rename/
reopen), the HTTP thread reads under the reader side — a request never sees
half a height.

## Index schema (v2)

| Table | Key | Holds |
|---|---|---|
| `blocks` | `height` | `block_id` (cometbft header hash), `prev_id`, `time_ms` (header time), `proposer`, `global_root`, `applied_count` (applied envelopes, claims excluded), `n_items` (all items). Secondary indexes: `idx_blocks_id` (`block_id`), `idx_blocks_time` (`time_ms, applied_count` — `/api/tps`; created `IF NOT EXISTS` on every open, so a v2 index gains it without a rebuild) |
| `items` | `(height, idx)` | `kind` (1 envelope, 2 claim, 0 empty), `code` (0 applied, else refused), `wire_id`, `intent_id`, `fee`, `op`, `has_effects`, `burned` — NULL where the node sent no value |
| `item_io` | `(height, idx, dir, pos)` | `dir` 0 consumed / 1 created, `coin_id`, `address`, `token`, `amount`, `unlock_block` |
| `item_records` | `(height, idx)` | the SYSTEM record an applied item wrote: `kind`, `validator`, `delegator`, `dest`, `amount`, `commission_bps`, `param_id`, `new_value`, `effective` |
| `item_names` | `(height, idx)` | HF-4: the chain name an applied NAME_REGISTER item registered (`dnac_v3_block` keys `"nm"`/`"pr"`): `name`, `price` (paid into the reward pool — not a burn), `owner` (the resolved address of the item's first consumed coin — every input is the one signer's; NULL when that coin's creating item is not indexed). Created `IF NOT EXISTS` on every open, so a v2 index gains it without a rebuild; an index advanced past the HF-4 switch by a binary without it lacks those names until rebuilt |
| `meta` | `key` | `schema_version` (2), `last_indexed_height`, `chain_id32`, `tip_height`, `supply_current`/`_burned`/`_genesis`, `supply_buckets` (one 97-byte blob: a has-flag byte, then 12 little-endian u64 — `current`, `reward_pool`, `treasury` pool 1..9, `unclaimed` — all from ONE `dnac_supply` reply; rewritten on every accepted observation, has = 0 for an older node; `exp_chain.h`), `active_stake` (one 25-byte blob: a has-flag byte, then 3 little-endian u64 — `stake`, `validators`, `at_tip`; rewritten on every accepted observation, has = 0 when the read failed; `exp_chain.h`) |

Records are a typed table, not a JSON column: the address history looks
items up by a record's validator/delegator/destination fingerprint (an
indexed column), and typed columns keep the stored form a direct copy of
the decoded fields.

**Consumed coins** are resolved at write time: a consumed row copies
address/token/amount from the coin's creating row when the index holds it
(creation always precedes consumption in chain order), and stays NULL
otherwise — a coin created at a block boundary (a reward payout, a stake
graduation release) is not an item, so its later spend shows an input
with no known owner.

**Balance — from the node, not the index.** The v1 `addr_stats`
accumulation is gone: block-boundary movements are not items, so a balance
replayed from items would be wrong (design item 4). `/api/address` instead
asks the network, per request, with the node's public `dnac_balance` query
(decision `docs/plans/decisions/2026-09-28-scan-v3-query.md` item 3a; wire
in `nodus/include/nodus/nodus.h`): per token the **total** of the address's
TRANSPARENT unspent coins, the part **spendable** in the next block
(coins still under an unstake/undelegate lock excluded — the exec's lock
gate at `tip + 1`) and the **coin count**. `dnac_utxo` (the coin list) stays
session-gated (C11) and is not used. The query is transparent-only by
decision and never covers a shielded pool.

- *Threading.* The HTTP thread uses its OWN chain handle (its own
  ephemeral identity and connection, opened in `main.c` next to the sync
  thread's), never the sync thread's connection; one serve thread, one
  handle, so no lock. The balance round trip runs BEFORE the index read
  lock is taken — a slow witness never holds the sync writer out. Failing
  to open that handle at startup is fatal, like the sync handle.
- *Failover.* `exp_chain_balance` tries every configured server (one
  rotation per attempt) before it reports a failure.
- *Cache.* The last 32 successful answers are reused for at most 5 s
  (`EXP_BALANCE_CACHE_TTL_MS`, monotonic clock); a failure is never cached.
  A balance may therefore trail the chain by up to 5 s plus the node's own
  commit lag.
- *Status.* `balance_status` is `"ok"` with the node's list (an empty list
  is a real zero) or `"unavailable"` with `balances: null` when every
  server failed — never a zero on an error. A node answers an error (seen
  here as `"unavailable"`) when the address holds more than 256 distinct
  tokens (`NODUS_DNAC_BALANCE_MAX_TOKENS`).

## Build

The explorer is a subdirectory of the messenger CMake build (it links
against `libdna`'s shared crypto + Nodus client SDK — there is no separate
build tree):

```bash
cd /opt/dna/messenger/build
cmake ..
make -j$(nproc)
```

Binary: `messenger/build/explorer/dna-explorerd`
Tests: build via the messenger tree above, then run
`messenger/build/explorer/test_explorer` directly — it is not wired into
`ctest` (no `add_test` for it). The tests need no network: the sync paths
run against fake `exp_sync_source_t` sources.

`messenger/build/explorer/test_rewards` is a second standalone test binary.
It needs only SQLite and writable temporary storage, and creates disposable
source/index fixtures under unique `mkstemp` paths; no nodes, keys, network,
live database or chain timing prerequisites. Its six groups exercise:
actual payouts and pending (including amounts above 2^53), sequence cursors
with gaps and over 100 recipients, coverage gaps versus a recorded empty
payday; stake releases (exact amounts above 2^53 at a non-payday epoch
boundary, `from`/`limit` paging with constant total/count, a release
interleaved with payouts in one boundary sequence space, an empty in-coverage
boundary returning `"0"` versus an uncovered/unindexed height or missing
source returning 503, the address `releases` list and its own
`release_before` cursor, and `paid_total` unchanged by releases);
invalid requests (including non-boundary release heights and misplaced or
duplicate `release_before`)/source binding/schema/rows, WAL snapshot
consistency and absence of source writes, and deterministic query-budget
exhaustion.
The header-only synthetic explorer fixture is intentionally sparse; these
tests cover rewards routing, not index continuity. Run both binaries; a
nonzero exit is a failure and no group has a skip path.

## Running

```
Usage: dna-explorerd [--config PATH] [--db PATH] [--rewards-db PATH] [--port N] [--once] [--verify-index] [--version]

  --config PATH    witness server list, "host port" per line (default /etc/dna-explorer.conf)
  --db PATH        sqlite index db path (default /var/lib/dna-explorer/index.db)
  --rewards-db PATH optional co-located Nodus database, opened read-only per request
  --port N         JSON API listen port (default 8390), 127.0.0.1 only
  --once           run a single sync tick and exit (smoke tests)
  --verify-index   consistency check of the index in --db (no network), print
                    OK/INCONSISTENT, exit 0/1: blocks are exactly heights
                    1..last_indexed_height; each block's item count equals
                    n_items and its applied envelopes equal applied_count;
                    every item has a block; every io/record row belongs to an
                    applied item; no refused item has effects.
  --version        print version and exit
```

### Config file format

One witness server per line: `<host> <port>`. Blank lines and lines starting
with `#` (after leading whitespace) are ignored. Malformed lines, an empty
server list, an exact duplicate `(host, port)` pair, or more than 16 servers
are all load errors — not truncation; a list of 17+ lines fails to load
entirely, it is not silently cut down to 16 (the duplicate check exists
because the F4 reset FSM's "≥2 distinct server" confirmation rule would
otherwise be satisfiable by one server listed twice — see
`exp_chain_config_load` / G3 below, "G6" in the v1 code comments). Example:

```
# Nodus Scan witness server list
203.0.113.10 4001
203.0.113.11 4001
# a third, for redundancy
203.0.113.12 4001
```

Production server IPs are **not** committed to this repo — see the internal
ops reference. Use `<witness-host> 4001` placeholders in any example checked
into git.

## HTTP API

All responses are JSON. All monetary fields (`fee`, `burned`, `name_price`, `amount`,
`total`, `spendable`, `new_value`, `supply_*`) are **decimal strings**, not JSON numbers — values
can exceed 2^53. Ids, addresses and `token_id` are lowercase hex strings;
native DNAC is the all-zero 64-byte `token_id`. `time` is the block
header's time in **milliseconds** since the Unix epoch. An item is
addressed by its **position** `"<height>:<index>"`; send the `:` as it is
(the API does not percent-decode).

| Endpoint | Description |
|---|---|
| `/api/stats` | `{indexed_height, tip_height, chain_id, supply_current, supply_burned, supply_genesis, reward_pool, treasury, unclaimed, circulating}` — any field not yet known is `null`. `chain_id` is the 32-byte `chain_id32`. `supply_genesis` is the fixed total supply. The supply buckets (decision `2026-09-30-scan-supply-buckets`): `reward_pool` (validator reward reserve left), `treasury` (array of 9 decimal strings, pool 1..9 in order: 1 Storage, 2 Compute, 3 Bandwidth, 4 Future services; 5-9 hold 0 on the live chain), `unclaimed` (genesis allocation not yet claimed) and `circulating` = `current − reward_pool − Σ treasury − unclaimed`, computed here from the SAME stored reply as the buckets (staked and Foundation coins count as circulating). All four are `null` when the node sends no buckets (an older node); `circulating` alone is `null` when a subtraction would go below zero — never a wrapped number. |
| `/api/blocks?before=<height>&limit=<n>` | `{blocks:[{height, block_id, time, proposer, applied_count, n_items}]}`, newest first (`limit` 1-100, default 25). |
| `/api/block/<height\|block_id>?from=<index>&limit=<n>` | `{block:{…, prev_id, global_root}, items:[item], next_from}` — one page of the block's items, index-ascending from `from` (default 0; `limit` default and max 100); `next_from` is the next page's first index, `null` on the last page. |
| `/api/tx/<wire_id\|intent_id\|height:index>` | `{tx:{item…, record}, inputs:[{coin_id, address, token_id, amount}], outputs:[{coin_id, address, token_id, amount, unlock_block}]}`. An input's `address`/`token_id`/`amount` are `null` when the coin's creating item is not in the index. A refused envelope has no ids — its position is its only address. |
| `/api/address/<fp>?before=<height:index>&limit=<n>` | `{address, balances:[{token_id, total, spendable, coins}] \| null, balance_status:"ok"\|"unavailable", items:[item], next_before}` — `balances` is the node's per-token list, token id ascending (`total`/`spendable` decimal strings, `coins` a number; see "Balance" above), `null` only with `"unavailable"`; `items` are the items touching the address (owner of a created or resolved consumed coin, or a record's validator/delegator/destination), newest first; `next_before` is the next page's cursor, `null` on a short page. |
| `/api/governance` | `{tip, indexed_height, records:[{position, height, index, time, param_id, param_name, new_value, effective_height, wire_id, intent_id}], truncated}` — every **applied** `chain_config` vote in the index (refused items carry no record), `(height, index)` ascending. `param_name` is the `DNAC_CFG_*` name of `param_id` (`dnac/include/dnac/dnac.h`, without the prefix — e.g. `HF2_ACTIVE`, `RULESET_GEN2`, `NAME_PRICE_3P`), `null` for an id this build does not know; `new_value` is a decimal string; `effective_height` is the block from which the value is in force. `tip` is the node's last reported committed height (`/api/stats` `tip_height`), `indexed_height` the index watermark — both `null` until known; a vote between the two is not listed yet. A rule is active when `tip ≥ effective_height`. Not a page: a hard cap of 1000 records, `truncated:true` when the index holds more. A chain_config row written from the genesis document (height 0 — HF-1's `GAS_PRICE_RAW_PER_UNIT` and `TOKEN_CREATE_FEE_RAW`) is not a block item and never appears. |
| `/api/tps` | `{now_ms, last_minute:{tx, blocks, seconds:60, tps}, last_hour:{tx, blocks, seconds:3600, tps}, next_payday:{height, blocks_left, avg_block_ms, est_ms}, paydays:[{height, time}], apy:{reward_pool, active_stake, active_validators, stake_at_tip, avg_block_ms, epochs_per_year, apy}, history:[{start_ms, tx, blocks, seconds, tps}]}` — throughput, payday and APY figures (the payday and APY parts: next row). Throughput of **applied** transactions (`applied_count`; refused items are not counted), read off the index by block time only (D4): `now_ms` is the time of the newest indexed block (highest height), never the explorer's clock, so the figures are reproducible from the index. The windows are half-open, `(now_ms − seconds·1000, now_ms]`: a block whose time is exactly `now_ms − 60000` is outside the last minute, one at `now_ms − 59999` inside. `history` is 24 hourly buckets, oldest first: `start_ms` is a UTC hour start (`start_ms % 3600000 == 0`), the newest bucket is the hour containing `now_ms`, a bucket holds the blocks with time in `[start_ms, start_ms + 1 h)` (up to `now_ms`), an hour with no block is a zero bucket. `seconds` is 3600, except the newest (in-progress) bucket: the seconds elapsed from its start to `now_ms`, rounded up, at least 1. `tps` = `tx / seconds` as a decimal **string** with exactly two decimals, rounded half up with integer arithmetic (`"0.35"`, `"3.00"`). An empty index answers `{now_ms:null, last_minute:null, last_hour:null, next_payday:null, paydays:[], apy:null, history:[]}`. Bounded cost: each span is a range scan of the covering index `idx_blocks_time` (`blocks(time_ms, applied_count)`, created on open — an existing index gains it without a rebuild) over at most 24 h of blocks; the payday pace fallback reads at most 100 heights and the paydays list at most 100 blocks, by primary key. |
| `/api/tps` — payday and APY | **Payday cadence**: rewards are paid at a block whose height is a multiple of **17 280** = `DNAC_EPOCH_LENGTH` 720 × `payout_interval_epochs` 24 (`nodus/src/witness/nodus_witness_v2_econ.c` `nodus_witness_v2_payday_apply`: `boundary_height % 720 == 0` and `(boundary_height / 720) % interval == 0`; the live genesis `payout_interval_epochs = 24`, `nodus/tools/genesis/testnet_v3.conf.template`) — the named constant `EXP_PAYDAY_INTERVAL_BLOCKS` (`exp_db.h`); the explorer does not read the genesis, so a different interval needs a new build. **`next_payday`**: `height` = the smallest multiple of 17 280 strictly above the newest indexed height, `blocks_left` = `height` − that height, `avg_block_ms` = the mean block interval over the last hour's indexed blocks ((newest − oldest time) / (count − 1), floored), or over the last 100 indexed heights when that hour holds fewer than 2 blocks, `est_ms` = `now_ms + blocks_left × avg_block_ms` — an estimate at the current block pace (blocks come every ~60 s when idle, faster when busy), `avg_block_ms`/`est_ms` `null` with fewer than 2 blocks indexed. **`paydays`**: past paydays, newest first, at most 100 — every multiple of 17 280 at or below the newest indexed height with its block `time`; `[]` before the first (block 17 280). This legacy index-only list carries no amount; `/api/paydays` supplies actual recorded totals when the optional local reward source is configured. Payouts are block-boundary rows, not block items; the owner-gated `dnac_addr_history` RPC is unchanged. A reward-pool difference is never used as a payday total. **`apy`** (an estimate, display only): `epochs_per_year = 31 557 600 s / (720 × avg_block_s)`, `avg_block_s` = the mean block interval over the last 24 h of block time (`avg_block_ms` here); `yearly_reward = reward_pool × (1 − (1 − 1/65536)^epochs_per_year)` — each epoch boundary pays `reward_pool >> 16` (`nodus_witness_v2_econ.c` settlement, `NODUS_V2_GEN_REWARD_DIVISOR_LOG2 = 16`, `nodus_witness_v2_gen.h`); `apy = yearly_reward / active_stake × 100` (percent). `reward_pool` comes from the stored supply buckets (`/api/stats`), `active_stake`/`active_validators` from the last accepted `dnac_validator_list_query` read (status ACTIVE, `self_stake + external_delegated`), `stake_at_tip` the tip it was read at. `reward_pool`/`active_stake` are decimal strings, `epochs_per_year`/`apy` two-decimal strings; each input is `null` when not known and `apy` is `null` unless every input is known and the stake is non-zero. It is an upper bound before validator commission: a member that misses the attendance bar leaves its share in the pool (the pool is debited only by what was credited), fees that refill the pool are ignored, and the active stake is the node's current table, not the frozen snapshot the reward is split by (stake is weighted as `floor(total_stake / 10^8)` there). Unlike the throughput figures, the pool and stake are the latest node observation, not a function of the index alone. |
| `/api/paydays?before=<height>&limit=<n>` | `{from_height, at_height, paydays:[{height, time, total, recipients, available}], next_before}` — scheduled payday heights at or below the indexed anchor, newest first; default 25, max 100. `before` is exclusive and `next_before` is the last shown height when another scheduled payday exists, otherwise null. An in-coverage payday with no payout rows has total `"0"`, recipients 0 and available true; before coverage it has null total/recipients and available false. |
| `/api/payday/<height>?from=<sequence>&limit=<n>` | `{height, time, total, recipients, payouts:[{address, amount, sequence}], next_from, from_height, at_height}` — native boundary payout rows for one scheduled payday, sequence ascending; `from` inclusive, default 0; limit default/max 100. `next_from` is the first unshown payout's sequence, null when complete; release rows can leave gaps. Whole-payday total/count remain constant across pages. Outside source coverage or beyond indexed height is 503; a non-payday height is 400. |
| `/api/releases/<height>?from=<sequence>&limit=<n>` | `{height, time, total, count, releases:[{address, amount, sequence}], next_from, from_height, at_height}` — native boundary **stake release** rows (`addr_history` `kind='release'`: graduation bond releases and delegation releases, one kind on the node — `nodus_witness_v2_epoch.c` `v2ep_release_utxo` → `nodus_witness_addr_index_boundary`) at one epoch boundary, sequence ascending; `from` inclusive, default 0; limit default/max 100. `address` is the coin's owner. `next_from` is the first unshown release's sequence, null when complete; payout rows share the boundary's sequence space, so sequences have gaps. Whole-height `total`/`count` remain constant across pages. A release is returned stake, never a reward — no payday total includes it. An in-coverage boundary with no release has total `"0"`, count 0, `releases:[]`. Outside source coverage or beyond indexed height is 503; height 0 or a height that is not a multiple of 720 (`EXP_EPOCH_BLOCKS`) is 400. The rows carry no coin id, output index or unlock height (the node-local table has no such columns), and a bond release is not distinguished from a delegation release. |
| `/api/rewards/<fp>?before=<height:sequence>&release_before=<height:sequence>&limit=<n>` | `{address, from_height, at_height, paid_total, pending, items:[{height, time, amount, sequence}], next_before, released_total, releases:[{height, time, amount, sequence}], next_release_before}` — actual recorded payouts in the current contiguous coverage run, newest `(height, sequence)` first; default 25, max 100. `paid_total` includes all recorded payouts within that run regardless of pagination and is **not current balance**; it never includes stake releases. `pending` is the source snapshot's current accrual, zero only for a valid absent row. `next_before` is the exclusive cursor of the last shown row when another row exists, else null. **Stake releases** are a separate list with its own cursor (the payout keys above are unchanged; a client that ignores the three release keys sees the old contract): `released_total` is the exact sum of the owner's release rows in the same coverage run, `releases` a page of them in the same order, `release_before` its exclusive cursor and `next_release_before` the next one. `limit` applies to each list; each request computes both lists from one snapshot under one request-wide budget. Send the colon literally. |
| `/api/search?q=<term>` | `{matches:[{type, target}]}` — every match: a decimal height → `block`; a `height:index` → `tx`; a 128-hex → `tx` (wire or intent id), `block` (block id), `address` (has indexed history); a chain name (lower-case, the chain's byte rule) → `name`, target = the registering item's position. An all-digit name also matches as a height: both are listed. Empty for a term that matches nothing. |

`item` = `{position, height, index, time, kind ("envelope"|"claim"|"empty"),
op ("spend", "burn", "token_create", "sysfund", "stake", "delegate",
"unstake", "undelegate", "validator_update", "chain_config", "claim",
"name_register" or null), code, refused (code ≠ 0), wire_id, intent_id,
fee, burned, name, name_price, name_owner}` — `name`/`name_price` (decimal
string)/`name_owner` are set on an applied name registration only, `null`
otherwise (`name_owner` also `null` when the owner is not in the index).
`record` = `{kind, validator, delegator, destination, amount,
commission_bps, param_id, new_value, effective_height}` or `null`.

Any endpoint returns `405` (`{"error":"method not allowed"}`) for non-GET
methods, `400` for malformed identifiers/pagination params, `413` for
request lines over 8 KB, `503` (`{"error":"index unavailable"}`) when the
index DB is transiently unset (e.g. an F4 reset's reopen failed), and `500`
on an internal query failure.

### Reward source and coverage

The four rewards endpoints (`/api/paydays`, `/api/payday`, `/api/releases`,
`/api/rewards`) require `--rewards-db`. They use only actual
`addr_history` rows with `kind='payout'` or `kind='release'` (each query
reads one kind; a release is never summed into a payout figure),
`v2_reward_accrual`,
`addr_history_mark` and `v2_blocks`. They never infer payouts from a supply
pool difference or a wallet balance, never backfill or fabricate rows, and
do not call or relax `dnac_addr_history`'s owner check.

Every request opens the source with `SQLITE_OPEN_READONLY` (plain filename,
no URI/`immutable`), begins one read transaction, matches the explorer's
latest copied block `(height, block_id)` against the source, then reads its
tip, complete-run marker and rewards in that same snapshot. A source behind
the index, different anchor, missing marker, `from_height < 1`, inverted
marker or `last_height != source tip` is unavailable. `from_height` is the
start of the current **unbroken** history run; older surviving rows before
it are excluded. Index locks are held only to copy/recheck the anchor and
scheduled block times; no source query holds the sync writer out. The
anchor is rechecked before success in case F4 reset the index during the
read. The source transaction is rolled back and its handle closed on every
exit.

For `/api/paydays`, `/api/payday` and `/api/releases`, `at_height` is the
indexed anchor; block dates come from indexed block time. For `/api/rewards`,
`at_height` is the source snapshot's current tip, possibly ahead of the
index, because accrual is current state and cannot be reconstructed at an
older index height. Its payout and release times are the recorded `ts`
seconds, checked before multiplication to milliseconds. All amounts,
including `paid_total`, `released_total` and `pending`, are exact raw-unit
decimal strings.

Queries use primary-key height ranges or `idx_addr_history_owner` owner
ranges, never a full-table payout scan. A request-wide 2,000,000-operation
SQLite progress budget (callbacks every 1,000 VM steps) bounds totals even
for very large histories; exhaustion returns 503, never a truncated total.
`/api/rewards` runs two owner ranges (payouts, then releases) under that one
budget, so a page of either list re-reads both. There are no busy retries.
SQL faults, malformed types/64-byte blobs, negative/out-of-range values,
non-native payout or release tokens and sum/time overflow
all return 503 `{"error":"rewards unavailable"}`. Existing endpoints remain
available when this optional source is unavailable.

## Deploy

1. **Nodes first:** the explorer needs Nodus with the scan-v3 query
   (`dnac_v3_block`, `dnac_supply` `chain_id32`/`tip`). Against an older
   node every tick fails ("not a version-3 node") and nothing is indexed.
   The supply buckets need Nodus with the `dnac_supply` bucket keys
   (`reward_pool`/`treasury`/`unclaimed`); against a node without them
   indexing continues and `/api/stats` answers the buckets as `null`.
2. **Backend (web server):**
   ```bash
   ssh <web-host> 'git -C /opt/dna pull && make -C /opt/dna/messenger/build -j$(nproc) && systemctl restart dna-explorerd'
   ```
   The first start of 0.2.0 drops the v1 index and re-indexes from height 1
   (see the top of this file) — `/api/stats` shows `indexed_height`
   climbing toward `tip_height` meanwhile.
   First-time setup: create the `dna-explorer` system user, `/var/lib/dna-explorer/`
   (writable by that user), `/etc/dna-explorer.conf` (witness server list —
   see format above, real IPs from internal ops reference), and install
   `deploy/dna-explorerd.service` to `/etc/systemd/system/`, then
   `systemctl daemon-reload && systemctl enable --now dna-explorerd`.
3. **Frontend (static site):** the Nodus Scan frontend is `website/scan/`,
   published to `scan.nodusnetwork.io` per `website/deploy/README.md` —
   **scp only, never rsync** (`feedback_no_rsync`). `website/scan/app.js`
   reads the JSON shapes above; publish it together with the 0.2.0 backend.
4. **nginx:** install `deploy/scan.cpunk.io.nginx.conf` to
   `/etc/nginx/sites-available/`, symlink into `sites-enabled/`,
   `nginx -t && systemctl reload nginx`.
5. **DNS + certbot (one-time only):** point the site's A/AAAA at the web
   server, then `certbot --nginx -d <site>` to provision the certificate the
   nginx config's `ssl_certificate` lines reference.

For payouts, co-locate the explorer with a Nodus node whose address-history
index is enabled and current. Add `--rewards-db /path/to/nodus.db` to the
existing explorer service command, retaining its existing arguments.
Provide the unprivileged `dna-explorer` user **read access only**: for a
root-owned Nodus service, set only the database and its existing `-wal` and
`-shm` files to owner/group `root:dna-explorer`, mode `0640`. Grant directory
traversal only as needed; keep source directories non-writable to the
explorer and preserve `ProtectSystem=strict`. Ensure recreated SQLite WAL
and SHM files retain that owner/group and read-only mode, and verify the
service user can open the live WAL database after a Nodus restart. Do not
grant access to key files, change key modes, recursively chmod/chown the
Nodus data directory, or run the explorer as root. A plain immutable copy
is not a live source: immutable mode would miss new WAL commits. If safe
WAL/SHM read access cannot be provisioned, leave the optional source
disabled rather than broadening permissions. Restart only the explorer
after its binary/service configuration update, then check all four
rewards endpoints against recorded source rows and existing endpoints.

Server deployment (installing the systemd unit, DNS, certbot, enabling the
service) requires explicit user approval before being executed
(`feedback_never_deploy_without_permission`) — this README documents the
procedure, it is not run autonomously.

## Determinism & threat model (summary)

The explorer is **outside consensus** — it writes nothing to the chain,
signs nothing, votes on nothing, and cannot cause a chain split.

**Determinism (index reproducibility, not consensus):**
- **D1** — the index is a function of the queried heights only: re-syncing
  from height 1 reproduces identical query results. The node's answer for a
  height is a pure function of its committed stores (design, Determinism).
- **D2** — every API list is ordered by an explicit total key (blocks by
  `height`, items and `/api/governance` records by `(height, index)`, io
  rows by `(dir, pos)`) — no
  hash-map iteration order reaches a response.
- **D3** — consumed-coin resolution reads only rows written earlier in
  chain order (lower height, or lower index in the same block, inserted
  earlier in the same transaction); `--verify-index` checks the stored
  index's structural invariants.
- **D4** — every displayed time is the block header's time; no wall-clock
  value is stored. `/api/tps` measures by block time too: its "now" is the
  newest indexed block's time, not the host clock — its throughput, payday
  and pace figures are a function of the index; its APY estimate also uses
  the last node observation of the reward pool and the active stake.
- **D5** — reward pages use `(height, sequence)` or `sequence` total order
  and one bound source snapshot. Current accrual is stamped with its source
  tip; history coverage is explicit, and unrecorded periods are unknown.

**Threat model (adversary: anonymous Internet client + a malicious or
buggy witness):**
- **G1** — no chain write path: the daemon never calls a TX-submit/spend
  Nodus API, enforced by a grep gate (`grep -rn "dnac_spend\|nodus_client_put\|nodus_client_dnac_spend\|dnac_send\|dnac_tx_submit" explorer/src/` must be empty).
- **G2** — witness cluster not exposed: public HTTP terminates at nginx;
  the daemon speaks outbound-only Nodus T2, no inbound path to any witness.
  The HTTP thread holds ONE chain client of its own, used for exactly one
  read-only query (`dnac_balance`, the address balance): an Internet
  request can make the daemon ask the configured servers for one address's
  totals (at most one attempt per configured server per request, successful
  answers cached 5 s) and nothing else. The sync thread's reads are
  `dnac_supply`, `dnac_v3_block` and `dnac_validator_list_query` (status
  ACTIVE, for the APY estimate) — all read-only.
- **G3** — no single server drives a destructive action: an index reset
  needs the same new `chain_id32` from ≥ 2 distinct configured servers over
  ≥ 2 polls (F4 FSM in `exp_chain.c`). A server's block is taken only
  whole: pages must agree on the header and continue the item indices, and
  a block announcing more than `EXP_BLOCK_MAX_ITEMS` items is refused.
- **G4** — bounded resource use: nginx `limit_req` on `/api/`; daemon-side
  hard caps (pagination ≤ 100, `/api/governance` ≤ 1000 records, request
  line ≤ 8 KB, parameterized SQL
  only, ≤ 256 heights per tick).
- **G5** — the API binds `127.0.0.1` and renders no HTML from chain data;
  the frontend inserts API data with `textContent` only.
- **G6** — honest trust display: the indexer trusts the configured servers'
  answers (no client-side re-verification of commits); the frontend states
  data is served from the witness cluster. A colluding majority of the
  configured servers lying consistently is out of scope (design, Threat
  Model).
