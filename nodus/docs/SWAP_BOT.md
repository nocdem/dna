# nodus-amm — the swap bot (USDT on Ethereum <-> NODUS)

TEST PHASE. The bot swaps USDT on Ethereum for NODUS and back at a price it
computes from its own pool, and lets people add and withdraw liquidity. In the
test phase it runs against Ethereum Sepolia with a test USDT (operator,
2026-11-10: "Tamam, o şekilde olsun. Test alanında olsun.", givens item 77).

Source: `nodus/tools/amm/`. Tests: `nodus/tests/test_amm_*.c`. Unit and config:
`nodus/deploy/nodus-amm.service`, `nodus/deploy/nodus-amm.conf.example`.
Install procedure: `nodus/docs/DEPLOY_RUNBOOK.md`, section 2.9 "Swap bot".

Governing records (local, not in git): `docs/plans/2026-11-08-swap-bot-plan.nodus1.md`
(the plan, sections 4, 15, 16, 17 for components, settings, pauses and restart
recovery, section 20 for what is deferred) and the operator's answers
`docs/plans/2026-11-06-bridge-givens.nodus1.md` (items 61, 75, 77, 97 and 98 for
the host, forwarding and limits). This file describes the code as built.

## 1. What it is

One Linux service, `nodus-amm`, that runs on the operator's node machine
(62.171.136.77, givens item 75), next to the witness and the faucet but as its
own user with its own keys. It listens on **127.0.0.1 only**
(`nodus/tools/amm/amm_http.c:835`, log line `amm_main.c:457`). The swap site
(swap.nodusnetwork.io, served by EU-6) forwards `/amm/…` to it (givens items 61,
97); the bot host opens no public port. No TLS here.

`nodus-amm --config <file>` (`amm_main.c:279-286`). It is the CMake target
`amm_main` with output name `nodus-amm` (`nodus/CMakeLists.txt:4034-4045`), built
only when libcurl is found (`nodus/CMakeLists.txt:4046-4050`). The program talks
to: its own local Nodus node (pinned identity), the configured Ethereum
JSON-RPC providers and the ETH price sources over HTTPS (libcurl).

Two keys, both the operator's to place; **the bot creates no key**:

- the Ethereum key: a file of exactly 64 hex digits, mode with no group or other
  bit (`amm_main.c:253-277`: the bot refuses to start otherwise);
- the Nodus identity directory, loaded read-only with
  `nodus_identity_load_readonly` (`amm_main.c:331`; it never writes, a missing or
  short file is an error, `src/crypto/nodus_identity.c:582-636`).

The bot refuses to start unless `foundation_eth` is the address of the Ethereum
key (`amm_main.c:380`) and `foundation_nodus` is the address of the Nodus
identity (`amm_main.c:406`).

## 2. What it does

All routes are JSON on 127.0.0.1 (`amm_http.h` header comment, `amm_http_route`
at `amm_http.c:696`). Any other path is 404, a wrong method is 405.

| Route | What it does |
|---|---|
| `POST /amm/quote` | The site's price question, unsigned: `{"direction":"usdt_to_nodus"\|"nodus_to_usdt","amount":"<raw>"}`. Answer: an approval (indicative output before the network fee, estimated fee, a random 32-bit request number, time it holds, where to pay) or `{"approved":false,"reason":"<word>"}`. A question holds no room (givens item 94). |
| `POST /amm/swap` | The paying extension's signed request. The answer is a delivery result only (`received` true or false with a reason). |
| `GET /amm/swap/<request number>` | The state of one swap. |
| `POST /amm/liquidity/quote` | The add question: one side's amount; answer is the exact pair at the pool's ratio and where to pay each side; below `liquidity_min_nodus` it answers `below_minimum`. |
| `POST /amm/liquidity/add` | The provider's two signed halves (Ethereum key and Nodus key). |
| `POST /amm/liquidity/withdraw` | The provider's signed withdrawal (Nodus key only). Acts after `liquidity_wait_eth_blocks` Ethereum blocks; this call pays nothing. |
| `GET /amm/status` | Reserves, settings in force (limits, validity, commission, chain id, signing name and origin, `usdtContract`, `liquidityMinNodus`), the three pause flags, `stopped`, in-flight and room left, the Foundation's addresses and the Nodus chain id (`amm_http.c:642-694`). |

**The two swap directions** (`amm_engine.h` header, "THE FLOW"):

1. The site asks the price (`/amm/quote`). The bot answers with its approval.
2. The user's extension sends the signed request to the bot, then pays: USDT to
   the Foundation's Ethereum address (`usdt_to_nodus`) or NODUS to the
   Foundation's Nodus address (`nodus_to_usdt`).
3. The bot's watchers see the payment (Ethereum through the provider quorum and
   the confirmation depth chosen by the amount; Nodus through its own node) and
   match it to the approval by sender, number and exact amount. A payment that
   matches no approval is held.
4. When it counts, the output is computed again from the pool of that moment and
   paid if it is at least the user's signed minimum after the network fee,
   otherwise refunded (givens item 93). The network fee is deducted from the
   payout and stays with the Foundation (givens items 80, 95). The payout is
   stored before it is sent and resubmitted as the SAME bytes after a restart.
5. In-flight USDT is limited to `inflight_max_usdt` (500 USDT); a payment that
   arrives at a full limit waits in line (givens item 94).

**Liquidity add and withdraw** (`amm_engine.h`, "LIQUIDITY ADD" and "LIQUIDITY
WITHDRAW"): others add and withdraw without stake. An add carries at least
`liquidity_min_nodus` (100,000 NODUS) with the USDT at the pool's ratio. Both
halves must arrive and count (USDT after `liquidity_wait_eth_blocks` Ethereum
blocks, NODUS after `liquidity_wait_nodus_blocks` Nodus blocks); then the add
commits in one journal transaction. The Foundation's start pool enters through
the first add: until an add has committed, every price question answers
`unavailable` (`amm_main.c:441`, givens item 91). A withdrawal pays only to
the stored address pair; a withdrawal where either side is nothing after its
network fee is refused whole.

**Status, pauses and stopping.** Three settings, each `0` or `1`, set in the
config file and applied by restart (plan section 16; `amm_cfg.h`):
`swaps_paused` (no new swap approvals), `liquidity_paused` (no new liquidity
requests), `payouts_paused` (nothing signed or broadcast; every payout stays
queued). `/amm/status` shows them and a `stopped` flag that is true while a swap
is in state `unknown` (`amm_engine.c:1638`). A required fact that cannot be read
(provider quorum missing, a Nodus block not held, a price known from too few
sources) leaves the swap in its state; it is never read as zero or "not found"
(plan section 17).

**Restart.** The journal is SQLite (WAL, `synchronous=FULL`); every state
transition is one transaction. After a restart: watchers resume from stored
cursors, stored-but-unconfirmed payouts are looked up on chain and never rebuilt,
open approvals are not re-checked against changed limits (plan section 17 and 15).
A second instance is refused by an exclusive lock on `lock_path`, taken before
any key is read (`amm_main.c:323-329`). On SIGTERM or SIGINT the HTTP loop stops,
the worker is joined and the secret key is wiped from memory (`amm_main.c:472-493`).

**Refusals to start** (each logs its reason): a config file that is refused
(unknown key, duplicate, malformed value, out of bounds, missing required key,
file over 16 KiB, NUL byte); a second instance; a missing key file or one readable
by others; an Ethereum key or Nodus identity that does not match its configured
address; a node whose address history is off or starts above
`nodus_start_height`; a provider that is refused; HTTP that cannot listen.

## 3. Bounds on the HTTP side

Request line <= 256 B, header block <= 4096 B, <= 32 header lines of <= 512 B,
path <= 160 B, body <= `http_max_body` (Content-Length only; Transfer-Encoding is
refused), no query strings, a connection cap `http_conn_cap` (1..64), one deadline
per request `http_timeout_ms`, `Connection: close`; an answer above
`http_max_response` is a 500, never cut (`amm_http.h` header comment). A JSON body
is one flat object of string values (at most 12 keys).

## 4. Where it runs, its files

Test phase: the operator's node machine, 62.171.136.77, next to the faucet
(givens item 75). Whether it stays there afterwards is not decided ("şu an
için").

| Path | What |
|---|---|
| `/usr/local/bin/nodus-amm` | the binary |
| `/etc/nodus-amm.conf` | the config (0640, `root:nodus-amm`); holds provider URLs that carry keys |
| `/etc/systemd/system/nodus-amm.service` | the unit |
| `/var/lib/nodus-amm/` | the unit's StateDirectory (0700, the only writable path) |
| `/var/lib/nodus-amm/journal.db` (+ `-wal`, `-shm`) | the journal |
| `/var/lib/nodus-amm/amm.lock` | the single-instance lock |
| `/var/lib/nodus-amm/keys/eth.key` | the Ethereum key (0600) |
| `/var/lib/nodus-amm/keys/nodus/` | the Nodus identity directory (six files) |

The unit's hardening is the faucet's (`nodus/deploy/nodus-faucet.service`): own
user, `StateDirectory`, `NoNewPrivileges`, `ProtectSystem=strict`,
`ProtectHome`, `PrivateTmp`, `PrivateDevices`, `ProtectKernelTunables`,
`ProtectControlGroups`, `RestrictAddressFamilies=AF_INET AF_UNIX`, empty
`CapabilityBoundingSet`, `UMask=0077`. Unknown, not read on a host: whether every
configured Ethereum provider and price source is reachable with IPv4 and the
local resolver only. If one is IPv6-only, `AF_INET6` has to be added to the unit.

## 5. Configuration (`/etc/nodus-amm.conf`)

`key = value` lines, strict. Comments only at the start of a line. Full commented
example: `nodus/deploy/nodus-amm.conf.example`. Parser: `nodus/tools/amm/amm_cfg.c`
(table `:29-68`, defaults `:111-142`, non-number keys `:289-352`). Every number
is at most UINT64_MAX/4. Units: USDT raw = 10^-6, NODUS raw = 10^-8.

| Key | Required | Default | Bounds | Source |
|---|---|---|---|---|
| `node_host`, `node_port` | yes | — | host non-empty, port 1..65535 | plan section 11 |
| `node_fp` | yes | — | 128 lowercase hex | plan section 11 |
| `chain_id` | yes | — | 64 lowercase hex | plan section 11 |
| `journal_path`, `lock_path` | yes | — | path, < 256 bytes | plan section 17 |
| `eth_key_path`, `nodus_key_dir` | yes | — | path, < 256 bytes | plan section 15 |
| `foundation_eth` / `foundation_nodus` | yes | — | 40 / 128 lowercase hex | plan section 15 |
| `eth_providers` | yes | — | 1..16 https URLs, comma separated, no duplicate | plan sections 9, 15 |
| `eth_quorum` | yes | — | 1..number of providers | givens item 58 |
| `eth_reorg_window_blocks` | yes | — | >= `eth_conf_count_3` | plan sections 9, 15 |
| `payout_final_depth_eth` | yes | — | >= 1 | plan section 10 |
| `http_max_body`, `http_max_response` | yes | — | >= 1 (`http_max_response` bounds the bot's own answers only) | plan section 6.4.7 |
| `http_port` | yes | — | 1..65535 | — |
| `http_conn_cap` | yes | — | 1..64 | — |
| `http_timeout_ms`, `worker_interval_ms`, `rpc_timeout_ms` | yes | — | >= 1 | — |
| `eth_start_height`, `nodus_start_height` | yes | — | >= 1 | — |
| `eth_max_scan_blocks`, `nodus_max_pages`, `nodus_resubmit_blocks`, `nodus_scan_blocks` | yes | — | >= 1 | — |
| `nodus_page_limit` | yes | — | 1..100 | — |
| `nodus_expiry_ahead` | yes | — | 1..100 | — |
| `eip712_name`, `expected_origin` | yes | — | printable ASCII, 1..127 | givens item 71 |
| `held_keeps_room` | yes | — | 0 or 1 | plan (no default) |
| `eth_chain_id` | no | 1 | >= 1 | givens item 77 |
| `usdt_contract` | no | mainnet USDT `dac17f95…1ec7` | 40 lowercase hex | plan section 5 |
| `eth_conf_bound_1_usdt` / `_2_usdt` | no | 100000000 / 1000000000 | >= 1, bound 1 below bound 2 | givens item 60 |
| `eth_conf_count_1` / `_2` / `_3` | no | 3 / 5 / 33 | 1..100, not decreasing | givens item 60 |
| `swap_max_usdt` | no | 100000000 | >= 1, <= `inflight_max_usdt` | givens item 19 |
| `inflight_max_usdt` | no | 500000000 | >= 1 | givens item 19 |
| `swap_min_usdt` | no | 1000000 | >= 1, <= `swap_max_usdt` | givens item 89 |
| `pool_start_usdt` / `pool_start_nodus` | no | 3000000000 / 3000000000000000 | >= 1 | givens item 20 |
| `liquidity_wait_eth_blocks` | no | 300 | >= 1 | givens item 25 |
| `liquidity_wait_nodus_blocks` | no | 3 | >= 1 | givens item 49 |
| `liquidity_min_nodus` | no | 10000000000000 | >= 1 | givens item 96 |
| `approval_valid_seconds` | no | 300 | >= 1 | givens item 72 |
| `quote_open_max` | no | 2000 | >= 1 | givens item 98 (main's proposal; no operator value) |
| `quote_read_fresh_ms` | no | 3000 | >= 1 | this build's proposal |
| `round_rows_max` | no | 1000 | >= 1 | this build's proposal |
| `commission` | no | 0 | 0 only | givens item 73 |
| `eth_max_response` | no | 4194304 | 1024..16777216 (the provider client's limits) | givens item 26; the bound of one Ethereum provider answer, measured block answers up to 35,955 bytes; a proposal of this build |
| `eth_price_sources` | no | all four | names from kraken, binance, bitfinex, coinbase, each once | plan section 10 |
| `eth_price_min_sources` | no | 3 | 1..4, <= number listed | givens item 74 |
| `eth_price_max_age_seconds` | no | 180 | >= 1 | givens item 74 |
| `swaps_paused`, `liquidity_paused`, `payouts_paused` | no | 0 | 0 or 1 | plan section 16 |

Cross-key rules refused at load: `eth_quorum` above the number of providers,
`swap_max_usdt` above `inflight_max_usdt`, `swap_min_usdt` above `swap_max_usdt`,
`eth_price_min_sources` above the number listed, bound 1 not below bound 2, counts
decreasing, `eth_reorg_window_blocks` below `eth_conf_count_3`
(`amm_cfg.c:388-426`). Values that the plan leaves "DEFERRED" have no default and
no value is named here; the Foundation writes them.

## 6. What it does NOT do (plan section 20, deferred; not built)

- No stake for later pools; only the Foundation's pool first (givens items 10-12).
- No replacement of an expired NODUS payout at a higher fee (givens item 97) and
  no fee raising of a stuck Ethereum payout; no coin joining on Nodus.
- No commission: the setting exists and only `0` is accepted (givens item 73).
- No value cap on liquidity adds, no upper limit (givens item 25).
- No operator tool to clear a `reversed` or `unknown` swap; no hand-move tool for
  incoming NODUS above the bot-key part (givens item 56).
- No key creation, no key rotation, no print-address command: the keys are
  placed by the operator; key file handling and rotation are deferred.
- No reconciliation of the ledger against the balances; no frozen-USDT handling.
- No TLS and no public port: the forwarding on EU-6 is the install step
  (runbook section 2.9), including the per-address limit of givens item 98.
- A per-internet-address limit is NOT in the bot: only the cap on open unpaid
  questions `quote_open_max` is (givens item 98 (a)); the per-address limit (b)
  belongs to the EU-6 forwarding and its number N is not decided.
- No mainnet use: the test phase runs on Sepolia with a test USDT.

## 7. Tests (written by the build, run by the ORCHESTRATOR)

`nodus/tests/test_amm_*.c`; run with `ctest -R amm`. `amm_main.c` itself needs a
live node and keys, so no test runs it; it is only compiled (comment at
`nodus/CMakeLists.txt:4034-4039`).
