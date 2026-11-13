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

Each Ethereum provider has one kept connection: one libcurl handle per provider,
used by one request at a time, with at most one cached connection
(`CURLOPT_MAXCONNECTS` 1; `amm_rpc_curl_new` / `amm_rpc_curl_post` in
`tools/amm/amm_eth_rpc.c`). An answer of a provider counts only when the chain id
was checked on the same connection that carried it (CHAIN ID in
`tools/amm/amm_eth_rpc.h`): a new connection is checked once with `eth_chainId`,
and an answer from a connection that was not kept, or whose check ran on another
connection, does not count. After a transfer that fails (`curl_easy_perform` does
not return `CURLE_OK`, for example a timeout or a transport error) the provider's
handle is re-created, so its next request opens a new connection, and that
connection is checked again.

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
| `POST /amm/quote` | The site's price question, unsigned, exactly one of two shapes. `usdt_to_nodus`: two keys, `{"direction":"usdt_to_nodus","amount":"<raw>"}`. `nodus_to_usdt`: three keys, `{"direction":"nodus_to_usdt","amount":"<raw>","destination":"0x<40 lowercase hex>"}`, where `destination` is the Ethereum address the user would receive the USDT at; the estimated fee in the answer is the fee the payer plans for `transfer(destination, number)` (below). A `nodus_to_usdt` question with only two keys is what a page script cached from before the bot's update sends: it gets HTTP 400 `{"approved":false,"reason":"page_out_of_date"}` and no estimate is computed for another address. A `destination` that is not `0x` and 40 lowercase hex digits, or a `destination` on `usdt_to_nodus`, is 400 `bad_request` (`amm_http.c:316-358`, `amm_http.h` header comment). Answer: an approval (indicative output before the network fee, estimated fee, a random 32-bit request number, time it holds, where to pay) or `{"approved":false,"reason":"<word>"}`. A question holds no room (givens item 94). The approval row stores the estimate only, not the destination: the swap's destination is the one the signed request carries. |
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
   The Ethereum payout's fee rule, its recovery and its books are described
   below under "The Ethereum fee of a USDT payout".
5. In-flight USDT is limited to `inflight_max_usdt` (500 USDT); a payment that
   arrives at a full limit waits in line (givens item 94).

**Ethereum provider reads run at the same time** (`tools/amm/amm_eth_fanout.h`).
When the Ethereum watcher asks the usable providers one question (qualify, the
tip, a block, the logs, a transaction record with its receipt, a record's
receipt with that provider's tip for the depth vote), or the payer asks one
(qualify, a balance, a gas estimate, a receipt with that provider's tip), it
asks all of them at once, one short-lived thread per provider, and examines the
answers in provider order only after every call has returned. The payer's other
reads (the tip, the nonce counts, the latest block's base fee and the suggested
priority fee, `qth` in `tools/amm/amm_eth_pay.c`) and its sending of a payment still ask the providers
one after another. The quorum rules that combine the answers are unchanged. A
group therefore waits for every one of its calls; each request keeps its own
transfer timeout, and no upper bound on the time of the whole group is set. If
a thread cannot be started, that provider's call runs on the calling thread
before the join, and the line
`AMM_FANOUT: k of n provider calls ran on the calling thread` is written.

**The Ethereum fee of a USDT payout** (`tools/amm/amm_eth_pay.h` header comment,
"FEES OF THE TRANSACTION", "SETTLEMENT", "RE-SEND", "REPLACEMENT"; plan
`docs/plans/approved/2026-11-13-evm-fee.md`). Every USDT payout and refund is
one type 2 transaction signed from the bot's key. The bot reads, at the provider
quorum (the Q-th largest answer of the usable providers, `eth_quorum`), the
latest block's base fee and `eth_maxPriorityFeePerGas`, and signs

- max priority fee per gas = the suggested priority fee;
- max fee per gas = 2 × the latest block's base fee + that priority fee
  (`amm_eth_pay_max_fee`, one pure function used by every planning path).

The gas limit is the quorum's `eth_estimateGas` of the exact call raised by 25 %,
rounded up. The Ethereum fee deducted from the user is the ceiling: gas limit ×
max fee per gas converted into USDT at the price median and rounded up (givens
item 95), so on a network whose base fee is large the user pays up to about twice
the base-fee part of what the chain finally charges; the difference stays with
the Foundation (givens item 80). A base fee, a priority fee, a price or an estimate
that cannot be read at the quorum leaves the payout unsent and retried; nothing
is signed with a guessed value. `eth_gasPrice` is no longer read by the payer or
the engine.

- **The estimate is the payout's own planning.** For `nodus_to_usdt` the price
  question carries the user's Ethereum address, and the `estimatedFee` the bot
  answers is computed by the same planning function the payout runs
  (`amm_eth_pay_plan`) for `transfer(that address, number)`, with the minimum
  ignored. The shown estimate therefore equals the deducted fee when the same
  providers answer, the base fee, priority fee, gas estimate, price median and
  pool are unchanged between the question and the decision, and the payout
  converges to a positive amount. A move of any of those between the two (a rising
  base fee on mainnet moves the ceiling by twice its change; an address that
  held USDT being emptied, or an empty address receiving USDT, changes the gas)
  can still make the real fee differ from the estimate, and a payout whose
  amount after the real fee falls below the user's signed minimum is refunded
  (givens items 82, 93). The site's minimum is computed from the estimate. The
  question path reuses the fee facts (usable providers, base fee, priority fee,
  max fee per gas) for `quote_read_fresh_ms`; the destination's gas estimate and
  the price conversion are read for every question. The decision, a re-send, a
  replacement and the shared-outage probe always read fresh facts.
- **A payout or refund whose transaction fails in a block is sent again
  automatically** (givens item 113 "3 a"). When the receipt at the final depth
  has status other than 1, the attempt is `failed` and the engine calls the
  payer's re-send, which signs and stores a new attempt (the next number, a new
  nonce) of the failed attempt's net with a new fee, before anything is sent. The
  failed attempt's fee and the new attempt's fee are both taken from the user's
  USDT: neither the Foundation's key nor the pool pays. The signed minimum is not
  compared again, so a re-sent payout can deliver less than that minimum by the
  later attempts' fees. An estimate that fails (a paused USDT contract, a short
  balance) sends nothing and costs nothing; the re-send is retried every round.
- **A payout that no block includes is replaced** (givens item 115 "1"). When the
  head attempt is `signed` or `submitted`, no attempt of its nonce has a receipt
  at the quorum, the nonce is not yet used, and the latest block's base fee at the
  quorum is above the head's max fee per gas, the payer signs a replacement with
  the same nonce and the same amount owed: the priority fee is the larger of the
  current suggestion and the old one raised by 10 % (at least 1 wei), the max fee comes from the
  same formula at the current base fee, and the replacement is refused if its max
  fee is not at least 10 % (and at least 1 wei) above the old one
  (`amm_eth_pay_replacement_fees`; the minimum a go-ethereum-family transaction
  pool accepts for a same-nonce replacement). The extra fee is deducted from the
  same user. The replacement is stored and the old attempt marked `replaced` in
  one journal transaction. If nothing is left after the replacement's fee, nothing
  is replaced and the old attempt waits, holding its nonce. Only one attempt of a
  nonce can be included: every step reads the receipt of every attempt of the
  nonce, settles the one that landed with its own amount, and marks the others
  `voided`.
- **A `submitted` payout is broadcast again as the same stored bytes** to every
  usable provider when the latest block is above the block of its last
  broadcast, at most once per new block, and stays `submitted` whatever the
  answers.
- **USDT that cannot cover its fee goes to the pool** (givens items 113 "3 a",
  114 "4 a"). A USDT refund, or a re-sent payout, whose amount is not above its
  fee is not sent: in one journal transaction the amount is added to the pool's
  USDT depth (NODUS depth and units unchanged, so every provider's share rises),
  the swap becomes `dropped`, and the fees of attempts that landed and failed are
  booked to the Foundation. The user receives nothing (givens item 89). A first
  NODUS to USDT payout whose amount is nothing after its fee is still refunded in
  NODUS at the decision, and a NODUS refund that is nothing after its Nodus fee
  keeps its earlier rule.
- **The Ethereum fee of a USDT refund is booked to the Foundation** like a payout's
  (`fee_booking`, `amm_journal_book_fee`: a `paid` NODUS to USDT payout or a
  `refunded` USDT to NODUS refund). The booked fee is the amount owed minus the
  amount the confirmed attempt delivered, the sum of the fees of the attempts that
  landed.
- **The ether of pending payouts is counted before signing.** The check before
  signing requires the bot's ether to cover the largest `gas limit × max fee per
  gas` of every other pending payout (per nonce, `signed`, `submitted` or
  `replaced`) plus the one being signed, and the USDT check subtracts the same
  per-nonce largest nets (`amm_journal_eth_pending`). A shortfall is
  `AMM_EP_FUNDS`: nothing is signed or stored, and it is retried. Payouts decided
  in one round therefore no longer each see the whole ether balance.
- **The journal is version 9** (`amm_journal.c`, `SCHEMA_VERSION`). `eth_attempts`
  gains the states `replaced` and `voided`, and its `UNIQUE(chain_id, nonce)`
  becomes a partial unique index over the attempts not in those two states, so a
  stuck payout can be replaced and a swap can hold several attempts. A version 8
  file is migrated when the new binary opens it: one transaction copies every
  `eth_attempts` row, compares the two row counts, drops the old table, renames the
  new one, creates the index and sets `user_version` 9; any failure rolls back, the
  file stays at version 8 and the bot does not start. Versions 1 to 7 are still
  refused and a version above 9 is refused. A binary of the earlier version cannot
  open a version 9 file. The deployment step is in the runbook, section 2.9.

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
| `eth_providers` | yes | — | 1..16 https URLs, comma separated, no duplicate | plan sections 9, 15; each provider gets one kept connection (section 1). Its log lines name it `provider-N`, never by its URL: "a new connection was made for this request", "post: transfer failed: … (new connections for this request: n; …); the handle re-created after the failure", and "every connection dropped, the handle re-created" (after a wrong chain id) |
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
| `eth_chain_id` | no | 1 | >= 1 | givens item 77; checked on every provider connection that carries a counted answer (section 1). Lines: "chain id N checked on this connection: the answer counts", or "the answer does not count: …" with the reason (its connection was not kept, the chain id could not be read on this connection, the connection reports another chain id, the check needed another new connection, the check ran on another connection) |
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
| `log_dir` | no | empty (no log file) | absolute path (starts with `/`), at most 200 bytes | operator 2026-11-11 "log DOSYASI!"; the bot also writes timestamped lines (`2026-11-11T18:12:40.123Z [WRN] AMM_RPC: text`, UTC) to `<log_dir>/nodus-amm.log`, rotated at 10 MiB to `nodus-amm.log.1` ... `.14` (oldest dropped; the sink is `nodus_log_file_open` in `src/nodus_log_shim.c`, opt-in, the stderr/journal lines stay; each stderr/journal line is written whole, also when several provider threads log at once, because `qgp_log_ring_add` holds the stderr stream lock for the whole line); a file that cannot be opened refuses the start. The unit's `LogsDirectory=nodus-amm` gives `/var/log/nodus-amm` |
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
- No replacement of an expired NODUS payout at a higher fee (givens item 97); no
  coin joining on Nodus. (A stuck Ethereum USDT payout is replaced with the same
  nonce and a failed one is sent again: see "The Ethereum fee of a USDT payout" in
  section 2.)
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
