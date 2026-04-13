# Concurrency and Lock Ordering

This document is the authoritative lock-ordering reference for the DNA
messenger C library. Every lock site in the codebase that participates in
cross-thread synchronization is annotated with a
`/* CONCURRENCY.md L{N}: {lock_name} */` comment referencing its level here.

Introduced by Phase 2 (concurrency-safety) which closed SEC-04, SEC-05,
THR-01, THR-02, and THR-03 as one coordinated batch.
See `.planning/phases/02-concurrency-safety/` for the plans and summaries.

## Acquisition Rule

A thread holding a lock at level N may acquire any lock at level greater
than N, but MUST NOT acquire a lock at level less than or equal to N.

Violating this rule creates a lock-ordering cycle and can cause deadlock.

## Same-Level Rule (L1 only)

A thread MUST NOT hold two locks at level L1 simultaneously. If a code
path needs to coordinate across two engine mutexes, it must release the
first before acquiring the second, or document the ordering as a sublevel
extension to this table.

## Ordering Table

| Level | Lock                                                 | Type              | File                                              | Introduced                            |
|-------|------------------------------------------------------|-------------------|---------------------------------------------------|---------------------------------------|
| L1    | engine mutex cluster (11 locks — see L1 section)     | pthread_mutex_t   | messenger/src/api/dna_engine_internal.h           | Pre-existing; documented Phase 2      |
| L2    | gek_lock                                             | pthread_rwlock_t  | messenger/messenger/gek.c                         | Phase 2, Plan 02-01 (SEC-04)          |
| L3    | g_nodus_init_mutex                                   | pthread_mutex_t   | messenger/dht/shared/nodus_init.c                 | Phase 2, Plan 02-03 (THR-02)          |
| L4    | g_queue_mutex                                        | pthread_mutex_t   | messenger/dht/shared/dht_offline_queue.c          | Pre-existing; documented Phase 2 (THR-01) |
| L5    | SQLite internal serialization                        | (SQLite managed)  | sqlite3 / SQLCipher                               | N/A — no user-space lock              |

## L1 — Engine Mutex Cluster

`struct dna_engine` in `messenger/src/api/dna_engine_internal.h` contains
eleven `pthread_mutex_t` members. Each one is at the same level (L1). A
thread MUST NOT hold more than one L1 lock simultaneously.

The eleven engine mutexes (field name — protects — internal header line):

- **`message_queue.mutex`** (line 712) — `dna_message_queue_t` entries,
  capacity, size, next_slot_id for the async fire-and-forget message send
  queue.
- **`name_cache_mutex`** (line 808) — `name_cache[]` fingerprint→display-name
  lookup table and `name_cache_count`.
- **`outbox_listeners_mutex`** (line 816) — `outbox_listeners[]` and
  `outbox_listener_count` for real-time offline-message notifications.
- **`contact_request_listener_mutex`** (line 822) — single
  `contact_request_listener` state (DHT token + active flag).
- **`ack_listeners_mutex`** (line 827) — `ack_listeners[]` and
  `ack_listener_count` for v15 delivery-confirmation listeners.
- **`channel_listeners_mutex`** (line 836) — `channel_listeners[]` and
  `channel_listener_count` for channel post notifications.
- **`group_listen_mutex`** (line 842) — `group_listen_contexts[]` and
  `group_listen_count` for group outbox listeners.
- **`event_mutex`** (line 848) — `event_callback`, `event_user_data`, and
  `callback_disposing` for the public event callback dispatch.
- **`task_mutex`** (line 855) — serializes producers into `task_queue`
  (the MPSC-via-mutex contract — see THR-03 section below), and paired
  with `task_cond` for worker thread wake-up.
- **`background_threads_mutex`** (line 869) — `setup_listeners_running`
  and `stabilization_retry_running` state flags (paired with
  `background_thread_exit_cond`).
- **`state_mutex`** (line 882) — protects engine lifecycle state
  transitions (v0.6.107+).

### Destroy-Path Invariant (SEC-05, Plan 02-02)

The engine destroy function `dna_engine_destroy` in
`messenger/src/api/dna_engine.c` must, in order:

1. Join `engine->backup_thread` if `atomic_load(&engine->backup_thread_running)`
   is true
2. Join `engine->restore_thread` if running (same atomic check)
3. `gek_clear_kem_keys()`
4. `dna_engine_cancel_all_outbox_listeners(engine)`
5. `messenger_free(engine->messenger)`
6. `qgp_secure_memzero(engine->session_password, ...)`

The two join steps MUST precede steps 3-6 because the backup/restore threads
can still be writing to `engine->messenger->backup_ctx` (and other engine
state) until the joins return. Do not reorder.

The `backup_thread_running` / `restore_thread_running` flags were promoted
from plain `bool` to `_Atomic bool` in Plan 02-02 because the destroy path
reads them without holding any engine mutex, and the background threads
write them from their own pthreads. Plain `bool` was a data race.

## L2 — gek_lock (SEC-04, Plan 02-01)

- **File:** `messenger/messenger/gek.c`
- **Type:** `pthread_rwlock_t` with `PTHREAD_RWLOCK_INITIALIZER` (default policy)
- **Protects:** `gek_kem_pubkey`, `gek_kem_privkey` (the two static KEM-key pointers)
- **Read pattern:** `rdlock` → copy pointer contents into a stack buffer →
  `unlock` → work with the copy → `qgp_secure_memzero` the stack buffer
- **Write pattern:** allocate new buffers outside the lock →
  `wrlock` → free-old → swap pointers → `unlock`

**Read sites (gek.c):**

| Function               | rdlock line | Purpose                              |
|------------------------|-------------|--------------------------------------|
| `gek_get_kem_pubkey`   | 241         | copy pubkey to caller stack          |
| `gek_encrypt_*` helper | 304         | copy privkey for local derivation    |
| `gek_decrypt_*` helper | 375         | copy privkey for KEM decapsulation   |
| (internal helper)      | 1609        | copy privkey for a secondary path    |
| (internal helper)      | 1733        | copy pubkey for a secondary path     |

**Write sites (gek.c):**

| Function              | wrlock line | Pattern                                        |
|-----------------------|-------------|------------------------------------------------|
| `gek_set_kem_keys`    | 615         | malloc+memcpy outside → wrlock → swap → unlock |
| `gek_clear_kem_keys`  | 639         | wrlock → memzero + free + NULL both pointers   |

### Writer-preference policy — NOT USED

`pthread_rwlockattr_setkind_np(..., PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP)`
is a glibc-only extension. It is absent from llvm-mingw winpthreads (verified
against the Windows cross-compile toolchain used in Phase 2) and is not
reliable on the Android NDK bionic pthreads. Phase 2 uses the default POSIX
rwlock policy for `gek_lock`. The GEK write path runs twice per session (set
on identity load, clear on destroy) so writer starvation is not a practical
concern. Future contributors: do NOT add `_np` attributes — they will break
the Windows cross-compile.

### Forbidden inside gek_lock critical section

No calls to `nodus_*`, `dht_*`, `sqlite3_*`, `contacts_db_*`, `messenger_*`.
The critical section must contain only pointer-check + memcpy + unlock (for
reads) or pointer swap + free (for writes).

## L3 — g_nodus_init_mutex (THR-02, Plan 02-03)

- **File:** `messenger/dht/shared/nodus_init.c`
- **Type:** `pthread_mutex_t` with `PTHREAD_MUTEX_INITIALIZER` (line 66)
- **Bootstrap:** First-time init is serialized via
  `pthread_once(&g_nodus_once, nodus_once_init)` (line 67). POSIX guarantees
  exactly-once semantics, so `nodus_once_init` does NOT take
  `g_nodus_init_mutex` — subsequent state reads/writes go through the mutex
  in the regular entry points.
- **Protects:** `g_stored_identity`, `g_connect_thread`, `g_config_loaded`,
  `g_config`, `g_status_cb`, `g_status_cb_data`, `g_known_nodes[]`,
  `g_known_node_count`.
- **Already atomic (not protected by this lock):** `g_initialized`,
  `g_connect_thread_running`.

### Callback pattern (required)

`on_state_change` acquires `g_nodus_init_mutex`, copies `g_status_cb` and
`g_status_cb_data` into local variables, releases the lock, and THEN invokes
the user callback with the local copies. User code NEVER runs while the
mutex is held — this prevents user callbacks from re-entering nodus APIs
under the lock.

### Forbidden inside g_nodus_init_mutex critical section

No calls to `nodus_singleton_*` or `nodus_client_*`. Re-entering nodus
client code while holding `g_nodus_init_mutex` would deadlock against the
nodus-internal singleton lock. If a nodus operation is needed around a
state mutation, the pattern is: (1) prepare the state change locally, (2)
release `g_nodus_init_mutex`, (3) perform the nodus operation, (4)
re-acquire `g_nodus_init_mutex` and commit the state change.

### Fork caveat

On platforms where `pthread_once_t` resets across `fork()`, this pattern
runs init twice. The messenger does not fork, so this is not a concern.

## L4 — g_queue_mutex (THR-01, Plan 02-04)

- **File:** `messenger/dht/shared/dht_offline_queue.c`
- **Type:** `pthread_mutex_t` with `PTHREAD_MUTEX_INITIALIZER` (line 23,
  pre-existing)
- **Protects:** `g_outbox_cache[]`
- **Sole live access path:** `dht_offline_queue_sync_pending` (lines
  ~1035-1080) is the only function in the file that touches
  `g_outbox_cache[]`. It locks `g_queue_mutex` at entry and unlocks at
  return. The lock site is annotated with `/* CONCURRENCY.md L4 */`.

### History (Phase 02-04)

Plan 02-04 deleted four dead static helper functions — `outbox_cache_init`,
`outbox_cache_find`, `outbox_cache_store`, `outbox_cache_store_ex` — per
CLAUDE.md No Dead Code rule. All four had zero callers anywhere in the
codebase. The also-dead `g_cache_initialized` flag was removed;
`g_outbox_cache[]` is zero-initialized by static storage at load time.

### `dht_dm_outbox.c` sibling — out of scope

`dht_dm_outbox.c` has its own `g_blob_cache_mutex` and `g_dm_cache_mutex`,
both consistently applied across all 13 access sites per the Phase 2
research audit. Phase 02-04 did NOT touch `dht_dm_outbox.c`. If a future
audit finds inconsistency there, a new plan should address it.

## L5 — SQLite Internal Serialization

SQLCipher is built against SQLite's default **serialized** threading mode
(`SQLITE_THREADSAFE=1`). A single connection handle may be used from
multiple threads; SQLite's internal mutex serializes access.

There is NO user-space lock at L5. Do NOT introduce a `db_lock` or
similar — it would be redundant with SQLite's own serialization and would
create a new lock-ordering liability (a second path to deadlock with
L1..L4 that would require another audit).

## Task Queue Contract (THR-03, Plan 02-04)

`dna_task_queue_t` in `messenger/src/api/dna_engine.c` (around lines
800-900) looks like an SPSC ring buffer in isolation but is driven
**MPSC-serialized-by-mutex**: every caller of `dna_task_queue_push` goes
through `dna_submit_task` (around line 890), which holds
`engine->task_mutex` (L1 cluster, the `task_mutex` member) around the
push. `dna_task_queue_pop` is called only from the single engine worker
thread.

### INVARIANT

1. Every call to `dna_task_queue_push` must be made while holding
   `engine->task_mutex`.
2. `dna_task_queue_pop` is called only from the single worker thread.

### Enforcement (debug builds only)

`dna_task_queue_t` carries a `#ifndef NDEBUG`-gated `pthread_t
task_mutex_owner` field. `dna_submit_task` sets
`engine->task_queue.task_mutex_owner = pthread_self()` immediately after
locking `engine->task_mutex`. `dna_task_queue_push` runs
`assert(pthread_equal(queue->task_mutex_owner, pthread_self()))` as its
first statement.

A future caller that bypasses `dna_submit_task` and pushes directly
without holding `task_mutex` will trip the assert and abort the debug
build — a real runtime trap, not a comment-only stub.

The mechanism is portable POSIX (`pthread_t`, `pthread_self()`,
`pthread_equal()` — all available on pthreads-w32 / llvm-mingw winpthreads
and Android NDK bionic) and zero-cost in release builds: verified with
`nm libdna.so` on the Release build, which shows zero references to
`task_mutex_owner`.

The THR-03 contract test
`messenger/tests/test_concurrency_task_queue_contract.c` exercises the
mechanism and is part of the Phase 2 regression suite.

### Hands off

Do NOT convert to lock-free MPSC with CAS. Do NOT remove the mutex to
enforce SPSC. The current combination is correct under the above invariant
and RC no-breaking-changes rules forbid reshaping it.

Future Flutter isolate / FFI work that submits tasks from multiple threads
is fine as long as every submission still goes through `dna_submit_task`
which takes `engine->task_mutex` and sets the owner.

## Running Tests Under ThreadSanitizer

TSan is not on by default because it conflicts with AddressSanitizer in the
same binary and slows builds. To run the Phase 2 concurrency tests under
TSan:

```bash
mkdir -p messenger/build-tsan && cd messenger/build-tsan
cmake -DENABLE_TSAN=ON ..
make -j$(nproc)
TSAN_OPTIONS=suppressions=../tests/tsan.supp ctest --output-on-failure \
    -R 'gek_concurrent|engine_destroy_during_backup|nodus_init_concurrent|concurrency_task_queue_contract'
```

The `tsan.supp` suppression file starts EMPTY. It has only a comment
header explaining the rules. Populate it ONLY in response to concrete
TSan output from a real run. Each suppression added must carry a comment
explaining the race pattern, why it is benign, the date added, and the
contributor who verified it.

See `messenger/tests/tsan.supp` for the header comment.

## Phase History

- **Phase 2 (this document introduced):** SEC-04, SEC-05, THR-01, THR-02,
  THR-03 closed as one coordinated batch. See
  `.planning/phases/02-concurrency-safety/` for the plans and summaries.
  - Plan 02-01 (SEC-04): L2 `gek_lock` added
  - Plan 02-02 (SEC-05): L1 destroy-path invariant + atomic promotion
  - Plan 02-03 (THR-02): L3 `g_nodus_init_mutex` added
  - Plan 02-04 (THR-01 + THR-03 + this doc): dead-code removal + task
    queue contract + L1..L5 table + opt-in TSan ctest target
