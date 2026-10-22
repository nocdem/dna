# nodus-faucet — the testnet faucet (NODUS + tUSDT)

TESTNET ONLY. The faucet hands out test coins so people can try the wallet and
the DEX without real money. Mainnet never has it (operator: "hiçbir zaman
mainnet'te USDT gibi bir şeyimiz olmayacak").

Source: `nodus/tools/faucet/`. Tests: `nodus/tests/test_faucet_*.c`. Unit and
config: `nodus/deploy/nodus-faucet.service`, `nodus/deploy/nodus-faucet.conf.example`.
Install and funding procedure: `nodus/docs/DEPLOY_RUNBOOK.md`, "Testnet faucet".

Governing records (local, not in git): `docs/plans/decisions/2026-10-22-testnet-test-tokens-faucet-dex.md`
(the operator's rules), `docs/plans/2026-10-22-testnet-faucet-design.md` section 6
(rev 2, the spec this code is built to), `docs/plans/2026-10-22-mm-dex-build-plan.md`
(package C, the HTTP API shared with the wallet).

## 1. What it is

One small Linux service, `nodus-faucet`, that runs on the operator's node
(62.171.136.77), next to the witness but as its own user with its own key. It
listens on **127.0.0.1 only**. The wallet's own site (EU-6) forwards `/faucet/…`
to it; the faucet host opens no public port.

It pays two kinds of claim, from ONE dedicated faucet wallet (a new key,
created at first start; the operator funds it):

| Claim | Who qualifies | Payout | Once per |
|---|---|---|---|
| START | the address owns **no name** and its **native NODUS total is 0** | 10 NODUS = 10^9 raw, one native spend | address |
| FULL | the address owns a chain name | 100 000 NODUS = 10^13 raw **and** 100 tUSDT = 10^8 raw, in **one** spend | name |

## 2. The operator's rules it implements (his sentences, recorded 2026-10-22)

- Empty address → one-time 10 NODUS: "Hicbireyi yoksa 10 nodus aordrop … ismi register etsin" and
  "NODUS bakiyesi 0" — an address whose NODUS balance is 0 qualifies, whatever tokens it holds.
- Once per chain name, 100 000 NODUS + 100 tUSDT: "Her chain name e 1 kere" and "100 $: 100 000 NODUS + 100 tUSDT…".
- One transaction: **"Tek işlem"** — FULL is ONE CORE SPEND (outputs [recipient NODUS][recipient tUSDT][tUSDT change?][NODUS change?]).
- START only without a name: **"Hayır"** — never START after FULL; an address with a name is never START.
- Fee ceiling per payout: **"0,1 NODUS"** = 10^7 raw. Above it the faucet pauses and waits for the operator; nothing is signed.
- Storage limit: **"Yeni istekleri durdur"** — at the journal's size ceiling new claims stop; paid markers are never deleted.
- Evidence: **"Kendi düğümüne güvensin"** — the faucet trusts its local node (identity pinned). An unreadable block is "unknown": the faucet stops and waits; it is never "unpaid".
- Script abuse is an accepted risk (**"Zaten bu testnet…"**): no captcha, no IP limit. The faucet's own funding bounds the loss.
- A NEW dedicated faucet wallet; the operator transfers the funds himself (**"Onemli mi . Zaten tranfwri ben yapicam"**).
- Host: **"nocdem düğümü (62.171.136.77)"**; reached through the wallet site: **"Cüzdan sitesi üzerinden"**.
- tUSDT: token id `7142460f5dd73ce7123905c423e1eb17fbff36f14b031e24837a4b6d7bedd5677baaa3a3e6015e6d6fc706b0b0d8799a88d7fd63f6d1e7807dbb88577b7c3b50`
  (block 305991), 6 decimals.

## 3. Configuration (`/etc/nodus-faucet.conf`)

`key = value` lines, strict (unknown key / duplicate / bad value / missing
required key = the service does not start). Full commented example:
`nodus/deploy/nodus-faucet.conf.example`.

| Key | Required | Default | Meaning |
|---|---|---|---|
| `node_host`, `node_port` | yes | — | the LOCAL node's client port (4001) |
| `node_fp` | yes | — | node identity pin, 128 hex (the session fails closed on any other server) |
| `chain_id` | yes | — | 64 hex; the faucet refuses to start on another chain and stops if the node's chain changes |
| `key_dir` | yes | — | the faucet's own identity (created with a new key on first start) |
| `journal_path` | yes | — | SQLite journal; `<path>.lock` is the single-instance lock |
| `token_id` | yes | — | tUSDT, 128 hex |
| `listen_port` | yes | — | HTTP, on 127.0.0.1 (the address is not configurable) |
| `full_native` / `full_token` / `start_native` | no | 10^13 / 10^8 / 10^9 | raw amounts |
| `fee_ceiling` | no | 10^7 | raw; above it a claim pauses |
| `expiry_ahead` | no | 90 | envelope expiry = tip + this (10..90) |
| `storage_ceiling` | no | 64 MiB | journal bytes (live db pages + wal) the faucet keeps below: new claims stop when the live bytes plus a 64 KiB reserve per open claim (and for the new one) reach it; a replacement attempt that would reach it is not signed (section 6) |
| `queue_cap` | no | 64 | open claims at once |
| `conn_cap` / `request_timeout_ms` | no | 16 / 5000 | HTTP connections / per-connection deadline (it also bounds the node reads of a claim request) |
| `poll_ms` | no | 4000 | worker cycle |

## 4. HTTP API (shared with the wallet)

127.0.0.1 only; `Connection: close`; JSON.

```
POST /faucet/claim            body {"address":"<128 lowercase hex>"}
GET  /faucet/claim/<claim_id>
GET  /faucet/status
claim answer : {"claim_id":"<hex>","state":"planned|paused|signed|submitted|confirmed|expired|unknown|refused","kind":"full|start|none","message":"…"}
status answer: {"open":bool,"paused":bool,"full_left":n,"start_left":n,"message":"…"}
```

- `refused` answers (not eligible, faucet empty, queue full, …) carry claim id `00000000000000000000000000000000` and kind `none`; `GET /faucet/claim/000…0` answers `refused / no claim`. No journal row is written for them.
- Asking again for an address that already has a claim returns THAT claim (de-dup); asking for a name that was already paid returns the paid claim — nothing is paid twice.
- HTTP codes: 200 for every decision (refusals included); 400 malformed address/body/id; 404 unknown path or claim; 405 wrong method; 411/413/431/501 request bounds; 408 request timeout; 503 the node/journal is unavailable, the request ran out of time, the faucet is stopped, or the connection cap is reached.
- Bounds (each pinned by `test_faucet_http`): request line ≤ 256 B, header block ≤ 4096 B, ≤ 32 header lines of ≤ 512 B, body ≤ 1024 B (Content-Length only; Transfer-Encoding refused), no query strings, connection cap, one deadline per connection.
- **Deadlines.** The connection's deadline (`request_timeout_ms`, counted from accept) is handed to the claim handler: every node read of a `POST /faucet/claim` waits on the node session only until that deadline (and never reconnects — only the worker rebuilds a down session); a request that is out of time is `503 refused`, nothing journalled. `GET /faucet/claim/<id>` reads the journal only; `GET /faucet/status` reads the journal and the worker's funds cache only — neither ever waits on the node. The worker's block scan takes the node session per page, not per block, so a slow scan does not hold it against a claim request.
- **Answers are sent to the end.** An answer is built once into the connection and sent through `POLLOUT` until complete, within the connection's deadline; a peer too slow to take ~1.3 KB inside the deadline is cut (the over-cap 503 and the 408 are best-effort single sends).
- `full_left` / `start_left` are the capacity of the faucet's own balance at the fee ceiling: FULL = min(NODUS / (10^13 + ceiling), tUSDT / 10^8); START = NODUS / (10^9 + ceiling). The NODUS is ONE pool shared by both. The balance is a cache the WORKER refreshes every cycle (re-read after 10 s); a cache older than 30 s, or one whose last refresh failed, is "the node could not be read" and closes `open`.
- `open` is false while the faucet is stopped (chain mismatch, a claim in state `unknown`, journal at its ceiling, node unreadable).

## 5. How a claim is decided and settled

**Decision** (handler, design 6.1): `dnac_name_of` and `dnac_balance` are read until
they report the SAME committed height (re-read up to 3 times, then "try again").
An error is never a zero and never "no name". Name found → FULL (key: the name).
No name and native total 0 → START (key: the address). Otherwise refused. The claim
and its permanent paid marker are written in one transaction; a funded-check
("faucet empty") runs first and writes nothing.

**Settlement** (one worker, one claim in flight, oldest first; design 6.4-6.5):

```
planned -> signed -> submitted -> confirmed
              \          \-> expired -> (replacement) signed ...
               \          \-> unknown   (a required block cannot be read completely)
 paused = nothing signed, waiting (fee above the ceiling, funding short, coin list incomplete,
          gas price not reported, claim history full, ...)
```

- `planned` / `paused`: read tip, rule-set generation (the pinned generation whose tuple EQUALS the node's `dnac_ruleset_info`), gas price and the faucet's own coins per token (`dnac_utxo` with `tok`); plan; compare the planner's fee with the ceiling **before** building; build and sign with the shared builder (it checks the payout tuple before AND after signing); our own read-back checks the recipient, amounts, token, change owner, fee and expiry again; then the signed bytes, intent id, wire id, input nullifiers, build tip and expiry are stored (fsync) together with the coin reservations. Only then is anything submitted.
  - **Gas price.** The node's `dnac_fee_info` answer must CARRY a `gas_price` (one unsigned value). A present `0` is a valid price (the rule is off). An absent, wrongly typed or repeated key (an older node, a malformed answer) is "not reported": the claim pauses ("the node did not report a gas price") and nothing is built — the price is never guessed as 0.
  - **Coins.** The node lists at most 100 coins per token, largest amount first. A list that fills the 100 is not "incomplete" by itself: the faucet plans over the listed (largest) coins whenever they cover the payout plus the fee — dust sent to the faucet does not stop it. Only when they do NOT cover it and the list was full is the claim paused as "coin list incomplete"; a complete list that does not cover it is "funding short".
- `signed` / `submitted`: submit the **same stored bytes** (again after every 3 blocks while the expiry is ahead); scan blocks from `build tip + 1` with `dnac_v3_block`, all pages. `confirmed` = the intent id found APPLIED. `expired` = the committed tip is past the expiry AND every block up to the expiry was scanned and did not apply it. A failed inclusion (no match) is not terminal. No submit answer ("duplicate", "CheckTx code N", timeout) moves a claim anywhere.
- `unknown`: ANY required block that cannot be read completely — the node does not hold it, or the read times out, a page is malformed or missing, or the node answers an internal error. The claim is recorded `unknown` (the scan cursor stays BEFORE that block), new claims are refused (503) and `/status` is closed until the evidence is readable again (the worker retries the scan every cycle and moves the claim back to `submitted` by itself) or the operator resolves it (section 7). A transient node outage therefore closes admission for its duration — by design: while the settlement evidence is unreadable the faucet does not take on more claims.
- A step is bounded in time (10 s of block scanning, then it resumes at the stored cursor) and one block walk has a 20 s budget; a walk that runs out of time is an unreadable block, never "not found".
- Replacement attempt only from `expired`, built from the old attempt's own coins first, and it must share at least one input with the expired attempt; with none of those coins left the claim pauses and nothing is signed. A replacement at the storage ceiling is not signed either (section 6).
- Restart: every state resumes from the journal — `planned` plans and signs; `signed`/`submitted` resubmit the same bytes and continue from the stored scan cursor; nothing is re-decided while a claim is open.

## 6. Journal and files

SQLite, WAL, `synchronous=FULL`, `BEGIN IMMEDIATE` for every transition. Tables:
`claims`, `paid` (permanent markers `full:<name>` / `start:<address>`), `attempts`
(stored envelope per signing), `reservations`. A second instance is refused by a
`flock` on `<journal_path>.lock`, taken before the key directory is touched.

**Storage ceiling.** The bytes counted are the database's LIVE pages (SQLite reuses
freed pages but never shrinks the file) plus the `-wal` file; an absent `-wal` is 0,
any other `stat()` failure is a fault (the faucet does not admit a claim on it).
- New claims are admitted only while live bytes + 64 KiB for every open claim and
  for the new one stay below `storage_ceiling` (this reserve is what the first
  signed attempt of an admitted claim lives in).
- A replacement attempt (a claim's second or later) first frees the envelope bytes
  of that claim's earlier, expired attempts — their wire id, intent id, inputs,
  expiry and scan cursor stay as evidence, and the paid markers are never touched —
  and is refused when the live bytes are still at the ceiling: the claim pauses
  ("the claim history is full; replacement signing is paused for the operator")
  and signs on its own once room returns. The envelope bytes of a `confirmed`
  claim are freed the same way.
- Every journal read is checked: a column of the wrong type, a text that does not fit
  its field or a blob of the wrong length fails the read (the caller sees a fault,
  never an empty value).

## 7. Operations

- Start order: config → the single-instance lock (`<journal_path>.lock`) → the identity → journal → node → chain guard → HTTP → worker. The lock comes BEFORE any key access, so two first starts cannot both generate a key.
- First start creates the faucet key in `key_dir` and logs `faucet address: <128 hex> — fund this address …`. The key is created atomically and durably: each file is written to a temporary name, fsynced and renamed, the directory is fsynced after every rename, and `nodus.pk` (the file the address derives from) is written LAST. An error while creating removes what this start wrote. A key directory that holds only SOME of the six identity files (`nodus.pk`, `nodus.sk`, `nodus.kyber_pk/sk`, `nodus.mlkem_pk/sk`) is REFUSED — never completed or regenerated over; restore the missing files or move the directory away. The identity is loaded with the read-only loader (never writes).
  `nodus-faucet --config <file> --print-address` prints the address alone; it takes the same lock, so **the service must be stopped** to use it (while it runs, read the address from its start-up log line).
- Funding is the operator's own transfer of NODUS and tUSDT to that address (few large coins; the node lists the 100 largest — see section 5 for what a full list means).
- `GET /faucet/status` (through the wallet origin or on 127.0.0.1) shows capacity and the stop/pause reason.
- A claim in state `unknown` keeps the faucet closed. The worker re-reads the missing block; if the node never serves it (pruned), the claim stays `unknown` and the faucet stays closed. There is NO command that forces a state in this version: the operator decides from independent evidence (an explorer or another node showing whether the intent id was applied) and the resolution tool is a deferred work item — do not edit the journal by hand (the reservations and the scan cursor must move with the state).
- A `paused` claim re-plans on every worker cycle by itself; raising `fee_ceiling` (restart), funding the faucet, a node that reports its gas price again, or room in the journal releases it.
- Every exit path of the service wipes the loaded secret key from memory (one cleanup path); the identity structure is zero-initialised before loading begins.

## 8. What it does NOT do

- No consensus change, no new hash, tag or domain string; payouts are ordinary CORE SPENDs signed with ML-DSA-87 through the shared client builder.
- No proof that the requester owns the address (the funds go TO the address; asking for someone else's only helps them), no captcha, no IP limit (accepted risk).
- No TLS and no public port (the wallet site's server forwards to it).
- No second instance, no clustering, no vault-owned names in the first version (operator: "İlk sürümde yok").
- Never mints; never partial-pays a FULL (both assets in one transaction or none).
- No retries that hide a failure: a failed read leaves the state unchanged and is logged; a node that cannot be read is never a "zero".
- tUSDT metadata / pin checks of the wallet are the wallet's concern, not the faucet's.

## 9. Tests (written, run by the ORCHESTRATOR)

| Test | What it proves | Requires | How it can lie |
|---|---|---|---|
| `test_faucet_cfg` | defaults = the operator's values; strict parsing | default build | parses strings only |
| `test_faucet_decision` | the decision rule, errors never zero, same-height reads, API behaviour (de-dup, paid markers, empty, queue cap, wrong chain); deadlines (past deadline = 503 with no node call, a live one is handed down, `/status` never calls the node and honours cache age); the gas-price presence decoder | default build, `/tmp` | stub node answers what is scripted and cannot wait (it records deadlines; the real adapter's mutex/RPC bounds are not stub-testable) |
| `test_faucet_journal` | legal state graph, atomic marker + claim, reservations, reopen persistence, unknown stops, storage ceiling; replacement compaction and ceiling; absent vs failing `-wal`; unreadable rows fail the read | default build, `/tmp` | no crash injection; bind failures and SQLite OOM cannot be forced (checked by construction) |
| `test_faucet_state` | payout shapes (real planner/builder/signer), fee ceiling pause, settlement, resubmission of the same bytes, failed inclusion, replacement rules, unknown on ANY unreadable block, restart from every state, coin-list problems (incl. a list at the cap), unreported gas price, replacement at the storage ceiling, one claim in flight | default build, `/tmp`; slower (ML-DSA signing) | scripted tip and blocks; no real mempool/chain |
| `test_faucet_http` | parser bounds, strict JSON, exact answer shapes, routes, deadline hand-down, a real loopback server (cap, 408, 413, 501, answers completed through POLLOUT) | default build, loopback on a kernel-chosen port | one thread drives both client and server; short writes are forced by a seam |

None needs a compile flag or environment variable. They leave nothing behind
(each removes its mkdtemp directory).
