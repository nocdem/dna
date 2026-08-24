# DNA Engine modular structure

The DNA Engine C API is split between the core dispatcher
`src/api/dna_engine.c` and domain modules in this directory.

## Current inventory

This checkout contains **23** `dna_engine_*.c` modules:

| Module | Responsibility |
|--------|----------------|
| `dna_engine_addressbook.c` | Wallet address book |
| `dna_engine_backup.c` | DHT backup and synchronization |
| `dna_engine_calls.c` | Voice-call signalling and orchestration |
| `dna_engine_channels.c` | Channels, posts and subscriptions |
| `dna_engine_contacts.c` | Contacts, requests and blocking |
| `dna_engine_debug_log.c` | Encrypted debug-log transport |
| `dna_engine_dnac.c` | DNAC wallet and witness operations |
| `dna_engine_follow.c` | Follow/unfollow state |
| `dna_engine_groups.c` | Group lifecycle and GEK operations |
| `dna_engine_helpers.c` | Shared engine helpers |
| `dna_engine_identity.c` | Identity creation, loading and profiles |
| `dna_engine_lifecycle.c` | Pause/resume and background lifecycle |
| `dna_engine_listeners.c` | DHT subscriptions and event listeners |
| `dna_engine_logging.c` | Local logging configuration |
| `dna_engine_media.c` | Media transfer and persistent outbox |
| `dna_engine_messaging.c` | Direct messaging and retry |
| `dna_engine_presence.c` | Presence publishing and lookup |
| `dna_engine_signing.c` | Public engine signing operations |
| `dna_engine_version.c` | Version publication and checking |
| `dna_engine_wall.c` | Personal-wall operations |
| `dna_engine_wall_poll.c` | Wall/feed polling |
| `dna_engine_wallet.c` | External-chain wallet and swaps |
| `dna_engine_workers.c` | Worker pool |

Do not use old module or line counts as architecture evidence. The tracked
directory and `messenger/CMakeLists.txt` are authoritative. In particular,
`dna_engine_feed.c` is not part of the current tree.

## Ownership model

| Concern | Location |
|---------|----------|
| Engine creation/destruction | `src/api/dna_engine.c` |
| Task queue and dispatch | `src/api/dna_engine.c` |
| Internal task/data definitions | `src/api/dna_engine_internal.h` |
| Public API declarations | `include/dna/dna_engine.h` |
| Domain handlers and wrappers | `src/api/engine/dna_engine_*.c` |
| Shared module includes/helpers | `src/api/engine/engine_includes.h` |

Most modules contain internal `dna_handle_*` task handlers and public
`dna_engine_*` wrappers. Exceptions should be verified from the module and
public header rather than inferred from the filename.

## Adding or moving an operation

An engine operation normally requires a coordinated update to:

1. the task enum and task-parameter union in
   `src/api/dna_engine_internal.h`;
2. the handler and public wrapper in the owning module;
3. the dispatch switch in `src/api/dna_engine.c`;
4. the declaration in `include/dna/dna_engine.h`;
5. FFI bindings and tests when the public surface changes;
6. `messenger/CMakeLists.txt` when a new module file is added.

Keep callback ownership, engine lifetime and worker-thread constraints aligned
with the neighboring operations in the same module.

## Build and test

From the repository root:

```bash
cmake -S messenger -B messenger/build -DCMAKE_BUILD_TYPE=Release
cmake --build messenger/build -j"$(nproc)"
ctest --test-dir messenger/build --output-on-failure
```

This README describes the current module boundary only. API signatures are
documented separately under [`messenger/docs/functions/`](../../../docs/functions/README.md)
and must be checked against the public headers before use.
