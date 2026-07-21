# DNAC Explorer (`dna-explorerd`)

Read-only block/transaction indexer + JSON API for `scan.cpunk.io`. Polls the
Nodus witness cluster over the client SDK, mirrors committed chain content
into a local sqlite index, and serves it over a small HTTP JSON API. The
static frontend lives in `cpunk/scan.cpunk.io/` (separate deploy path).

Design doc: `docs/plans/2026-07-21-dnac-explorer-design.md` (local-only, not
committed — see `feedback_plans_dir_local_only`). Determinism/threat-model
summary below is grounded in that doc's §7/§8.

## Component overview

- `src/exp_chain.{c,h}` — read-only wrapper around the Nodus client SDK
  (`nodus/include/nodus/nodus.h`). Owns an ephemeral Dilithium5 identity
  (generated at open, never persisted), rotates across the configured witness
  server list on failure. Also hosts the F4 chain-reset FSM
  (`exp_reset_fsm_feed`) that gates destructive index wipes behind
  multi-witness, multi-poll confirmation.
- `src/exp_sync.{c,h}` — the sync loop: walks the chain by ledger `seq`
  (`exp_chain_ledger_range`, served by the witness's `dnac_ledger_range`
  query), fetches each TX (`dnac_tx`), and writes rows into the index DB.
- `src/exp_extract.{c,h}` — deserializes raw TX bytes into index rows
  (`exp_tx_row_t` / `exp_io_row_t`), sourcing timestamps only from the
  deserialized TX, never the witness response envelope.
- `src/exp_db.{c,h}` — sqlite index schema, prepared-statement queries,
  `addr_stats` incremental balance maintenance, and `exp_db_verify_addr_stats`
  (the `--verify-index` recompute-and-diff check).
- `src/exp_http.{c,h}` — the JSON HTTP API (`exp_http_serve`), bound to
  `127.0.0.1` only.
- `src/exp_json.{c,h}` — minimal JSON emission helpers (money fields as
  decimal strings — see below).
- `src/main.c` — CLI entry point / daemon lifecycle.
- `tests/` — unit + integration tests (`ctest`), run from the messenger build
  tree (see Build below).
- `deploy/dna-explorerd.service` — systemd unit (sample).
- `deploy/scan.cpunk.io.nginx.conf` — nginx reverse-proxy + static-site
  config (sample).

## Build

The explorer is a subdirectory of the messenger CMake build (like dnac, it
links against `libdna`'s shared crypto + Nodus client SDK — there is no
separate build tree):

```bash
cd /opt/dna/messenger/build
cmake ..
make -j$(nproc)
```

Binary: `messenger/build/explorer/dna-explorerd`
Tests: build via the messenger tree above, then run
`messenger/build/explorer/test_explorer` directly — it is not wired into
`ctest` (no `add_test` for it).

## Running

```
Usage: dna-explorerd [--config PATH] [--db PATH] [--port N] [--once] [--verify-index] [--version]

  --config PATH    witness server list, "host port" per line (default /etc/dna-explorer.conf)
  --db PATH        sqlite index db path (default /var/lib/dna-explorer/index.db)
  --port N         JSON API listen port (default 8390), 127.0.0.1 only
  --once           run a single sync tick and exit (smoke tests)
  --verify-index   recompute addr_stats from tx_io and diff against the
                    stored values in --db, print OK/MISMATCH, exit 0/1. No network.
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
`exp_chain_config_load` / G6). Example:

```
# scan.cpunk.io witness server list
203.0.113.10 4001
203.0.113.11 4001
# a third, for redundancy
203.0.113.12 4001
```

Production server IPs are **not** committed to this repo — see the internal
ops reference. Use `<witness-host> 4001` placeholders in any example checked
into git.

## HTTP API

All responses are JSON. All monetary/supply fields (`fee`, `amount`,
`balance`, `supply_current`, `supply_burned`, `supply_genesis`) are emitted
as **decimal strings**, not JSON numbers — this avoids float-precision loss
on values that can exceed 2^53 in JS clients. `chain_id`, hashes, addresses,
and `token_id` are lowercase hex strings. Native DNAC is represented by an
all-zero 64-byte `token_id`.

| Endpoint | Method | Description |
|---|---|---|
| `/api/stats` | GET | `indexed_seq`, `tip_seq`, `indexed_height`, `chain_id`, `supply_current`, `supply_burned`, `supply_genesis`. Any field not yet known is `null`. |
| `/api/blocks?before=<height>&limit=<n>` | GET | Paginated block list, newest first (`limit` 1-100, default 25). |
| `/api/block/<height\|hash>` | GET | One block (accepts a decimal height or a 128-hex block hash) + its tx summaries. 404 if not found. |
| `/api/tx/<hash>` | GET | One TX by 128-hex hash: summary (`fee` as string), `ios[]` (inputs/outputs, `amount` as string), and `raw` (hex-encoded raw TX bytes). 404 if not found. |
| `/api/address/<fp>?before=<seq>&limit=<n>&utxos=1` | GET | Native DNAC balance (signed decimal string, credits-minus-debits) + tx_count, paginated tx history. `utxos=1` adds a `"source":"witness-live"` passthrough section (live Nodus query, NOT from the index — explicitly out of the D1 reproducibility claim; reports `{"error":"unavailable"}` if the live witness call fails). |
| `/api/search?q=<term>` | GET | Precedence-free multi-match: reports every match among tx hash / block hash / block height / address fingerprint for `q` (128-hex or decimal). Empty `matches[]` for a query that matches nothing or isn't hex/decimal shaped — not an error. |

Any endpoint returns `405` (`{"error":"method not allowed"}`) for non-GET
methods, `400` for malformed identifiers/pagination params, `413` for
request lines over 8 KB, `503` (`{"error":"index unavailable"}`) when the
index DB is transiently unset (e.g. mid-reset, during an F4-triggered
reopen), and `500` on an internal query failure.

## Deploy

1. **Backend (web server):**
   ```bash
   ssh <web-host> 'git -C /opt/dna pull && make -C /opt/dna/messenger/build -j$(nproc) && systemctl restart dna-explorerd'
   ```
   First-time setup: create the `dna-explorer` system user, `/var/lib/dna-explorer/`
   (writable by that user), `/etc/dna-explorer.conf` (witness server list —
   see format above, real IPs from internal ops reference), and install
   `deploy/dna-explorerd.service` to `/etc/systemd/system/`, then
   `systemctl daemon-reload && systemctl enable --now dna-explorerd`.
2. **Frontend (static site):** `scp` each changed file under
   `cpunk/scan.cpunk.io/` to `/var/www/scan.cpunk.io/` on the web server —
   **scp only, never rsync** (`feedback_no_rsync`). Files: `index.html`,
   `block.html`, `tx.html`, `address.html`, `app.js`, `style.css`, favicons.
3. **nginx:** install `deploy/scan.cpunk.io.nginx.conf` to
   `/etc/nginx/sites-available/`, symlink into `sites-enabled/`,
   `nginx -t && systemctl reload nginx`.
4. **DNS + certbot (one-time only):** point `scan.cpunk.io` A/AAAA at the web
   server, then `certbot --nginx -d scan.cpunk.io` to provision the
   certificate the nginx config's `ssl_certificate` lines reference.

Server deployment (installing the systemd unit, DNS, certbot, enabling the
service) requires explicit user approval before being executed
(`feedback_never_deploy_without_permission`) — this README documents the
procedure, it is not run autonomously.

## Determinism & threat model (summary)

The explorer is **outside consensus** — it writes nothing to the chain,
signs nothing, votes on nothing, and cannot cause a chain split. Full detail:
`docs/plans/2026-07-21-dnac-explorer-design.md` §7/§8 (local-only).

**Determinism (index reproducibility, not consensus):**
- **D1** — the index DB is a pure function of committed chain content;
  re-syncing from genesis reproduces identical query results.
- **D2** — every API list is ordered by an explicit total key (blocks by
  `height DESC`, txs/address history by ledger `seq`) — no hash-map
  iteration order reaches a response.
- **D3** — `addr_stats` incremental maintenance and its from-scratch
  recomputation use the same `tx_io` derivation; `--verify-index` is the
  automated diff check.
- **D4** — all displayed timestamps come from chain data (deserialized TX /
  block headers); the witness response envelope's `time(NULL)` field is
  banned from the index.

**Threat model (adversary: anonymous Internet client + a compromised
witness):**
- **G1** — no chain write path: the daemon never calls a TX-submit/spend
  Nodus API, enforced by a grep gate (`grep -rn "dnac_spend\|nodus_client_put\|nodus_client_dnac_spend\|dnac_send\|dnac_tx_submit" explorer/src/` must be empty).
- **G2** — witness cluster not exposed: public HTTP terminates at nginx;
  the daemon speaks outbound-only Nodus T2, no inbound path to any witness.
- **G3** — bounded resource use: nginx `limit_req` on `/api/`; daemon-side
  hard caps (pagination ≤ 100, request line ≤ 8 KB, parameterized SQL only).
- **G4** — read-only, public data only: no auth, no session, no PII beyond
  what any public UTXO chain explorer inherently exposes (accepted, mirrors
  `project_presence_privacy_c12`).
- **G5** — honest trust display: the indexer trusts witness responses (no
  client-side BFT cert re-verification in v1); frontend states data is
  served from the witness cluster.
- **G6** — poisoning blast-radius bounded: no single witness response can
  wipe/rebuild the index — destructive chain-reset actions require
  multi-witness, multi-poll confirmation (F4 FSM in `exp_chain.c`).
