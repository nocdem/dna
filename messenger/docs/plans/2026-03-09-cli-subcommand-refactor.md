# CLI Subcommand Refactor — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Refactor the flat CLI command structure into grouped subcommands (`identity create`, `contact add`, `message send`, etc.)

**Architecture:** Two dispatchers exist — `main.c` (single-command mode) and `cli_commands.c:execute_command()` (REPL mode). Both must be refactored to a two-level dispatch: first parse the group name, then the subcommand. The `channel` group already uses this pattern and serves as the template. No `cmd_*` function signatures change — only the dispatch layer and help text.

**Tech Stack:** C (POSIX), CMake build system

---

## Command Mapping (Old → New)

### `identity` (16 subcommands)
| Old command | New command | Function |
|-------------|------------|----------|
| `create <name>` | `identity create <name>` | `cmd_create()` |
| `restore <mnemonic>` | `identity restore <mnemonic>` | `cmd_restore()` |
| `delete <fp>` | `identity delete <fp>` | `cmd_delete()` |
| `list` / `ls` | `identity list` | `cmd_list()` |
| `load <fp>` | `identity load <fp>` | `cmd_load()` |
| `whoami` | `identity whoami` | `cmd_whoami()` |
| `change-password` | `identity change-password` | `cmd_change_password()` |
| `register <name>` | `identity register <name>` | `cmd_register()` |
| `name` | `identity name` | `cmd_name()` |
| `lookup <name>` | `identity lookup <name>` | `cmd_lookup()` |
| `lookup-profile <id>` | `identity lookup-profile <id>` | `cmd_lookup_profile()` |
| `profile [field=val]` | `identity profile [field=val]` | `cmd_profile()` |
| `set-nickname <fp> <n>` | `identity set-nickname <fp> <n>` | `cmd_set_nickname()` |
| `get-avatar <fp>` | `identity get-avatar <fp>` | `cmd_get_avatar()` |
| `get-mnemonic` | `identity get-mnemonic` | `cmd_get_mnemonic()` |
| `refresh-profile <fp>` | `identity refresh-profile <fp>` | `cmd_refresh_profile()` |

### `contact` (15 subcommands)
| Old command | New command | Function |
|-------------|------------|----------|
| `contacts` | `contact list` | `cmd_contacts()` |
| `add-contact <id>` | `contact add <id>` | `cmd_add_contact()` |
| `remove-contact <fp>` | `contact remove <fp>` | `cmd_remove_contact()` |
| `request <fp> [msg]` | `contact request <fp> [msg]` | `cmd_request()` |
| `requests` | `contact requests` | `cmd_requests()` |
| `request-count` | `contact request-count` | `cmd_request_count()` |
| `approve <fp>` | `contact approve <fp>` | `cmd_approve()` |
| `deny <fp>` | `contact deny <fp>` | `cmd_deny()` |
| `block <id>` | `contact block <id>` | `cmd_block()` |
| `unblock <fp>` | `contact unblock <fp>` | `cmd_unblock()` |
| `blocked` | `contact blocked` | `cmd_blocked()` |
| `is-blocked <fp>` | `contact is-blocked <fp>` | `cmd_is_blocked()` |
| `check-inbox <id>` | `contact check-inbox <id>` | `cmd_check_inbox()` |
| `sync-contacts-up` | `contact sync-up` | `cmd_sync_contacts_up()` |
| `sync-contacts-down` | `contact sync-down` | `cmd_sync_contacts_down()` |

### `message` (15 subcommands)
| Old command | New command | Function |
|-------------|------------|----------|
| `send <fp> <msg>` | `message send <fp> <msg>` | `cmd_send()` |
| `messages <fp>` | `message list <fp>` | `cmd_messages()` |
| `messages-page <fp> <n> <off>` | `message page <fp> <n> <off>` | `cmd_messages_page()` |
| `delete-message <id>` | `message delete <id>` | `cmd_delete_message()` |
| `mark-read <fp>` | `message mark-read <fp>` | `cmd_mark_read()` |
| `unread <fp>` | `message unread <fp>` | `cmd_unread()` |
| `check-offline` | `message check-offline` | `cmd_check_offline()` |
| `listen` | `message listen` | `cmd_listen()` |
| `queue-status` | `message queue-status` | `cmd_queue_status()` |
| `queue-send <fp> <msg>` | `message queue-send <fp> <msg>` | `cmd_queue_send()` |
| `set-queue-capacity <n>` | `message queue-capacity <n>` | `cmd_set_queue_capacity()` |
| `retry-pending` | `message retry-pending` | `cmd_retry_pending()` |
| `retry-message <id>` | `message retry-message <id>` | `cmd_retry_message()` |
| `backup-messages` | `message backup` | `cmd_backup_messages()` |
| `restore-messages` | `message restore` | `cmd_restore_messages()` |

### `group` (15 subcommands)
| Old command | New command | Function |
|-------------|------------|----------|
| `group-list` | `group list` | `cmd_group_list()` |
| `group-create <name>` | `group create <name>` | `cmd_group_create()` |
| `group-send <uuid> <msg>` | `group send <uuid> <msg>` | `cmd_group_send()` |
| `group-info <uuid>` | `group info <uuid>` | `cmd_group_info()` |
| `group-members <uuid>` | `group members <uuid>` | `cmd_group_members()` |
| `group-invite <uuid> <fp>` | `group invite <uuid> <fp>` | `cmd_group_invite()` |
| `group-messages <uuid>` | `group messages <uuid>` | `cmd_group_messages()` |
| `group-sync <uuid>` | `group sync <uuid>` | `cmd_group_sync()` |
| `sync-groups` | `group sync-all` | `cmd_sync_groups()` |
| `sync-groups-up` | `group sync-up` | `cmd_sync_groups_up()` |
| `sync-groups-down` | `group sync-down` | `cmd_sync_groups_down()` |
| `group-publish-gek <uuid>` | `group publish-gek <uuid>` | `cmd_group_publish_gek()` |
| `gek-fetch <uuid>` | `group gek-fetch <uuid>` | `cmd_gek_fetch()` |
| `invitations` | `group invitations` | `cmd_invitations()` |
| `invite-accept <uuid>` | `group invite-accept <uuid>` | `cmd_invite_accept()` |
| `invite-reject <uuid>` | `group invite-reject <uuid>` | `cmd_invite_reject()` |

### `channel` (10 subcommands — ALREADY DONE, no changes)
Existing: `channel create|get|delete|discover|post|posts|subscribe|unsubscribe|subscriptions|sync`

### `wallet` (5 subcommands)
| Old command | New command | Function |
|-------------|------------|----------|
| `wallets` | `wallet list` | `cmd_wallets()` |
| `balance <idx>` | `wallet balance <idx>` | `cmd_balance()` |
| `send-tokens <w> <net> <tok> <to> <amt>` | `wallet send <w> <net> <tok> <to> <amt>` | `cmd_send_tokens()` |
| `transactions <idx>` | `wallet transactions <idx>` | `cmd_transactions()` |
| `estimate-gas <id>` | `wallet estimate-gas <id>` | `cmd_estimate_gas()` |

### `dex` (2 subcommands)
| Old command | New command | Function |
|-------------|------------|----------|
| `dex-quote <from> <to> <amt> [dex]` | `dex quote <from> <to> <amt> [dex]` | `cmd_dex_quote()` |
| `dex-pairs` | `dex pairs` | `cmd_dex_pairs()` |

### `network` (7 subcommands)
| Old command | New command | Function |
|-------------|------------|----------|
| `online <fp>` | `network online <fp>` | `cmd_online()` |
| `dht-status` | `network dht-status` | `cmd_dht_status()` |
| `pause-presence` | `network pause-presence` | `cmd_pause_presence()` |
| `resume-presence` | `network resume-presence` | `cmd_resume_presence()` |
| `refresh-presence` | `network refresh-presence` | `cmd_refresh_presence()` |
| `network-changed` | `network changed` | `cmd_network_changed()` |
| `bootstrap-registry` | `network bootstrap-registry` | `cmd_bootstrap_registry()` |

### `version` (2 subcommands)
| Old command | New command | Function |
|-------------|------------|----------|
| `publish-version ...` | `version publish ...` | `cmd_publish_version()` |
| `check-version` | `version check` | `cmd_check_version()` |

### `sign` (2 subcommands)
| Old command | New command | Function |
|-------------|------------|----------|
| `sign <data>` | `sign data <data>` | `cmd_sign()` |
| `signing-pubkey` | `sign pubkey` | `cmd_signing_pubkey()` |

### `debug` (7 subcommands)
| Old command | New command | Function |
|-------------|------------|----------|
| `log-level [lvl]` | `debug log-level [lvl]` | `cmd_log_level()` |
| `log-tags [tags]` | `debug log-tags [tags]` | `cmd_log_tags()` |
| `debug-log <on\|off>` | `debug log <on\|off>` | `cmd_debug_log()` |
| `debug-entries [n]` | `debug entries [n]` | `cmd_debug_entries()` |
| `debug-count` | `debug count` | `cmd_debug_count()` |
| `debug-clear` | `debug clear` | `cmd_debug_clear()` |
| `debug-export <file>` | `debug export <file>` | `cmd_debug_export()` |

---

## Implementation Tasks

### Task 1: Add group dispatcher helpers to `cli_commands.h`

**Files:**
- Modify: `messenger/cli/cli_commands.h`

**Step 1: Add group help function declarations**

Add before the `COMMAND PARSER` section (before line 506):

```c
/* ============================================================================
 * GROUP DISPATCHERS — one per command group
 * ============================================================================ */

/* Each dispatcher parses subcmd from argv and calls the appropriate cmd_* function.
 * argc/argv are the FULL original argv (optind points to group name).
 * subcmd_offset = optind + 1 (first arg after group name).
 * Returns: result code (0=success). */

int dispatch_identity(dna_engine_t *engine, int argc, char **argv, int subcmd_offset);
int dispatch_contact(dna_engine_t *engine, int argc, char **argv, int subcmd_offset);
int dispatch_message(dna_engine_t *engine, int argc, char **argv, int subcmd_offset);
int dispatch_group(dna_engine_t *engine, int argc, char **argv, int subcmd_offset);
/* dispatch_channel already exists inline in main.c — will be extracted */
int dispatch_wallet(dna_engine_t *engine, int argc, char **argv, int subcmd_offset);
int dispatch_dex(dna_engine_t *engine, int argc, char **argv, int subcmd_offset);
int dispatch_network(dna_engine_t *engine, int argc, char **argv, int subcmd_offset);
int dispatch_version(dna_engine_t *engine, int argc, char **argv, int subcmd_offset);
int dispatch_sign(dna_engine_t *engine, int argc, char **argv, int subcmd_offset);
int dispatch_debug(dna_engine_t *engine, int argc, char **argv, int subcmd_offset);

/* REPL-mode group dispatchers (use strtok for arg parsing) */
int dispatch_identity_repl(dna_engine_t *engine, const char *subcmd);
int dispatch_contact_repl(dna_engine_t *engine, const char *subcmd);
int dispatch_message_repl(dna_engine_t *engine, const char *subcmd);
int dispatch_group_repl(dna_engine_t *engine, const char *subcmd);
int dispatch_wallet_repl(dna_engine_t *engine, const char *subcmd);
int dispatch_dex_repl(dna_engine_t *engine, const char *subcmd);
int dispatch_network_repl(dna_engine_t *engine, const char *subcmd);
int dispatch_version_repl(dna_engine_t *engine, const char *subcmd);
int dispatch_sign_repl(dna_engine_t *engine, const char *subcmd);
int dispatch_debug_repl(dna_engine_t *engine, const char *subcmd);
```

**Step 2: Build to verify header compiles**

Run: `cd messenger/build && cmake .. && make -j$(nproc)`
Expected: PASS (declarations only, no missing symbols yet)

**Step 3: Commit**

```bash
git add messenger/cli/cli_commands.h
git commit -m "refactor: add group dispatcher declarations to cli_commands.h"
```

---

### Task 2: Implement `dispatch_identity` and `dispatch_identity_repl`

**Files:**
- Modify: `messenger/cli/cli_commands.c` — add at end, before `execute_command()`

**Step 1: Implement argv-based dispatcher (for main.c)**

```c
/* ============================================================================
 * GROUP DISPATCHERS (argv-based, for main.c single-command mode)
 * ============================================================================ */

int dispatch_identity(dna_engine_t *engine, int argc, char **argv, int sub) {
    if (sub >= argc) {
        fprintf(stderr, "Usage: identity <subcommand>\n");
        fprintf(stderr, "Subcommands: create, restore, delete, list, load, whoami, change-password,\n");
        fprintf(stderr, "  register, name, lookup, lookup-profile, profile, set-nickname,\n");
        fprintf(stderr, "  get-avatar, get-mnemonic, refresh-profile\n");
        return 1;
    }
    const char *subcmd = argv[sub];

    if (strcmp(subcmd, "create") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: identity create <name>\n"); return 1; }
        return cmd_create(engine, argv[sub + 1]);
    }
    else if (strcmp(subcmd, "restore") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: identity restore <24-word mnemonic>\n"); return 1; }
        /* Concatenate remaining args as mnemonic */
        static char mnemonic[2048];
        mnemonic[0] = '\0';
        for (int i = sub + 1; i < argc; i++) {
            if (i > sub + 1) strcat(mnemonic, " ");
            strcat(mnemonic, argv[i]);
        }
        return cmd_restore(engine, mnemonic);
    }
    else if (strcmp(subcmd, "delete") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: identity delete <fingerprint>\n"); return 1; }
        return cmd_delete(engine, argv[sub + 1]);
    }
    else if (strcmp(subcmd, "list") == 0) {
        return cmd_list(engine);
    }
    else if (strcmp(subcmd, "load") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: identity load <fingerprint>\n"); return 1; }
        return cmd_load(engine, argv[sub + 1]);
    }
    else if (strcmp(subcmd, "whoami") == 0) {
        cmd_whoami(engine); return 0;
    }
    else if (strcmp(subcmd, "change-password") == 0) {
        return cmd_change_password(engine);
    }
    else if (strcmp(subcmd, "register") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: identity register <name>\n"); return 1; }
        return cmd_register(engine, argv[sub + 1]);
    }
    else if (strcmp(subcmd, "name") == 0) {
        return cmd_name(engine);
    }
    else if (strcmp(subcmd, "lookup") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: identity lookup <name>\n"); return 1; }
        return cmd_lookup(engine, argv[sub + 1]);
    }
    else if (strcmp(subcmd, "lookup-profile") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: identity lookup-profile <name|fp>\n"); return 1; }
        return cmd_lookup_profile(engine, argv[sub + 1]);
    }
    else if (strcmp(subcmd, "profile") == 0) {
        if (sub + 1 >= argc) {
            return cmd_profile(engine, NULL, NULL);
        }
        /* Check for field=value */
        char *eq = strchr(argv[sub + 1], '=');
        if (!eq) {
            fprintf(stderr, "Usage: identity profile [field=value]\n");
            return 1;
        }
        *eq = '\0';
        return cmd_profile(engine, argv[sub + 1], eq + 1);
    }
    else if (strcmp(subcmd, "set-nickname") == 0) {
        if (sub + 2 >= argc) { fprintf(stderr, "Usage: identity set-nickname <fp> <nickname>\n"); return 1; }
        return cmd_set_nickname(engine, argv[sub + 1], argv[sub + 2]);
    }
    else if (strcmp(subcmd, "get-avatar") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: identity get-avatar <fp>\n"); return 1; }
        return cmd_get_avatar(engine, argv[sub + 1]);
    }
    else if (strcmp(subcmd, "get-mnemonic") == 0) {
        return cmd_get_mnemonic(engine);
    }
    else if (strcmp(subcmd, "refresh-profile") == 0) {
        if (sub + 1 >= argc) { fprintf(stderr, "Usage: identity refresh-profile <fp>\n"); return 1; }
        return cmd_refresh_profile(engine, argv[sub + 1]);
    }
    else {
        fprintf(stderr, "Unknown identity subcommand: %s\n", subcmd);
        return 1;
    }
}
```

**Step 2: Implement REPL dispatcher**

```c
/* ============================================================================
 * GROUP DISPATCHERS (REPL-mode, strtok-based)
 * ============================================================================ */

int dispatch_identity_repl(dna_engine_t *engine, const char *subcmd) {
    if (!subcmd) {
        printf("Usage: identity <subcommand>\n");
        printf("Subcommands: create, restore, delete, list, load, whoami, change-password,\n");
        printf("  register, name, lookup, lookup-profile, profile, set-nickname,\n");
        printf("  get-avatar, get-mnemonic, refresh-profile\n");
        return 1;
    }

    if (strcmp(subcmd, "create") == 0) {
        char *name = strtok(NULL, " \t");
        if (!name) { printf("Usage: identity create <name>\n"); return 1; }
        return cmd_create(engine, name);
    }
    else if (strcmp(subcmd, "restore") == 0) {
        char *mnemonic = strtok(NULL, "");
        if (!mnemonic) { printf("Usage: identity restore <24-word mnemonic>\n"); return 1; }
        return cmd_restore(engine, mnemonic);
    }
    /* ... (same pattern for all 16 subcmds, using strtok for args) ... */
    else {
        printf("Unknown identity subcommand: %s\n", subcmd);
        return 1;
    }
}
```

> **NOTE:** The full REPL dispatcher follows the exact same pattern as the argv dispatcher, but uses `strtok(NULL, " \t")` instead of `argv[sub + N]` for argument parsing. The code shown above is abbreviated — the actual implementation covers all 16 subcommands.

**Step 3: Build**

Run: `cd messenger/build && cmake .. && make -j$(nproc)`
Expected: PASS

**Step 4: Commit**

```bash
git add messenger/cli/cli_commands.c
git commit -m "refactor: implement identity group dispatchers"
```

---

### Task 3: Implement remaining group dispatchers (contact, message, group, wallet, dex, network, version, sign, debug)

**Files:**
- Modify: `messenger/cli/cli_commands.c`

Each dispatcher follows the identical pattern established in Task 2. Implement in order:

1. `dispatch_contact` / `dispatch_contact_repl` — 15 subcmds
2. `dispatch_message` / `dispatch_message_repl` — 15 subcmds
3. `dispatch_group` / `dispatch_group_repl` — 16 subcmds
4. `dispatch_wallet` / `dispatch_wallet_repl` — 5 subcmds
5. `dispatch_dex` / `dispatch_dex_repl` — 2 subcmds
6. `dispatch_network` / `dispatch_network_repl` — 7 subcmds
7. `dispatch_version` / `dispatch_version_repl` — 2 subcmds
8. `dispatch_sign` / `dispatch_sign_repl` — 2 subcmds
9. `dispatch_debug` / `dispatch_debug_repl` — 7 subcmds

**Key mappings to watch:**

- `dispatch_version` argv: parse `--lib`, `--app`, `--nodus`, `--lib-min`, `--app-min`, `--nodus-min` flags for `publish` subcommand (copy the existing flag parser from main.c line 571-596)
- `dispatch_message` argv: `retry-message` takes `int64_t` (use `strtoll`)
- `dispatch_message` argv: `page` takes 3 args: `<fp> <limit> <offset>`
- `dispatch_group`: extract existing `channel`-style dispatch from main.c lines 964-1050 as reference
- `dispatch_dex` argv: `quote` has optional 4th arg `dex_filter`

**Step 1: Implement all 9 dispatcher pairs**

Follow the mapping tables from the top of this document exactly. Each dispatcher:
- Prints subcommand help when no subcommand given
- Validates arg count before calling `cmd_*`
- Returns 1 on usage error, forwards `cmd_*` return otherwise

**Step 2: Build**

Run: `cd messenger/build && cmake .. && make -j$(nproc)`
Expected: PASS (0 warnings)

**Step 3: Commit**

```bash
git add messenger/cli/cli_commands.c
git commit -m "refactor: implement all group dispatchers (contact, message, group, wallet, dex, network, version, sign, debug)"
```

---

### Task 4: Refactor `main.c` — replace flat dispatch with group dispatch

**Files:**
- Modify: `messenger/cli/main.c`

**Step 1: Replace `print_usage()` with grouped help**

Replace the entire `print_usage()` function body with:

```c
static void print_usage(const char *prog_name) {
    printf("DNA Connect CLI v%s\n\n", DNA_VERSION_STRING);
    printf("Usage: %s [OPTIONS] <group> <command> [args...]\n\n", prog_name);
    printf("Options:\n");
    printf("  -d, --data-dir <path>   Data directory (default: ~/.dna)\n");
    printf("  -q, --quiet             Suppress banner/status messages\n");
    printf("  -h, --help              Show this help\n");
    printf("  -v, --version           Show version\n");
    printf("\n");
    printf("Command Groups:\n");
    printf("  identity    Identity management (create, restore, load, profile, ...)\n");
    printf("  contact     Contact management (add, remove, request, block, ...)\n");
    printf("  message     Messaging (send, list, queue, backup, ...)\n");
    printf("  group       Group chat (create, invite, send, sync, ...)\n");
    printf("  channel     Channels (create, post, subscribe, ...)\n");
    printf("  wallet      Wallet operations (balance, send, transactions, ...)\n");
    printf("  dex         DEX trading (quote, pairs)\n");
    printf("  network     Network & presence (online, dht-status, ...)\n");
    printf("  version     Version management (publish, check)\n");
    printf("  sign        Signing (data, pubkey)\n");
    printf("  debug       Debug & logging (log-level, entries, export, ...)\n");
    printf("\n");
    printf("Run '%s <group> help' for subcommand details.\n", prog_name);
    printf("\n");
    printf("Examples:\n");
    printf("  %s identity create alice\n", prog_name);
    printf("  %s contact add bob\n", prog_name);
    printf("  %s message send nox \"Hello!\"\n", prog_name);
    printf("  %s wallet balance 0\n", prog_name);
    printf("  %s dex quote ETH USDC 1.0\n", prog_name);
}
```

**Step 2: Update `needs_identity` check**

Replace the existing `needs_identity` check (lines 358-364) with:

```c
    /* Groups/subcommands that do NOT need an identity loaded */
    int needs_identity = 1;

    if (strcmp(command, "help") == 0) {
        needs_identity = 0;
    }
    else if (strcmp(command, "identity") == 0 && optind + 1 < argc) {
        const char *sub = argv[optind + 1];
        if (strcmp(sub, "create") == 0 || strcmp(sub, "restore") == 0 ||
            strcmp(sub, "delete") == 0 || strcmp(sub, "list") == 0 ||
            strcmp(sub, "help") == 0) {
            needs_identity = 0;
        }
    }
    else if (strcmp(command, "version") == 0 && optind + 1 < argc) {
        const char *sub = argv[optind + 1];
        if (strcmp(sub, "check") == 0 || strcmp(sub, "help") == 0) {
            needs_identity = 0;
        }
    }
    else if (strcmp(command, "debug") == 0) {
        needs_identity = 0;  /* debug commands work without identity */
    }
```

**Step 3: Replace the entire dispatch block**

Replace the entire `if/else if` chain (lines 384-1081) with:

```c
    /* ====== GROUP DISPATCH ====== */
    if (strcmp(command, "help") == 0) {
        print_usage(argv[0]);
        result = 0;
    }
    else if (strcmp(command, "identity") == 0) {
        result = dispatch_identity(g_engine, argc, argv, optind + 1);
    }
    else if (strcmp(command, "contact") == 0) {
        result = dispatch_contact(g_engine, argc, argv, optind + 1);
    }
    else if (strcmp(command, "message") == 0) {
        result = dispatch_message(g_engine, argc, argv, optind + 1);
    }
    else if (strcmp(command, "group") == 0) {
        result = dispatch_group(g_engine, argc, argv, optind + 1);
    }
    else if (strcmp(command, "channel") == 0) {
        result = dispatch_channel(g_engine, argc, argv, optind + 1);
    }
    else if (strcmp(command, "wallet") == 0) {
        result = dispatch_wallet(g_engine, argc, argv, optind + 1);
    }
    else if (strcmp(command, "dex") == 0) {
        result = dispatch_dex(g_engine, argc, argv, optind + 1);
    }
    else if (strcmp(command, "network") == 0) {
        result = dispatch_network(g_engine, argc, argv, optind + 1);
    }
    else if (strcmp(command, "version") == 0) {
        result = dispatch_version(g_engine, argc, argv, optind + 1);
    }
    else if (strcmp(command, "sign") == 0) {
        result = dispatch_sign(g_engine, argc, argv, optind + 1);
    }
    else if (strcmp(command, "debug") == 0) {
        result = dispatch_debug(g_engine, argc, argv, optind + 1);
    }
    else {
        fprintf(stderr, "Unknown command group: '%s'\n", command);
        fprintf(stderr, "Run '%s help' for available groups.\n", argv[0]);
        result = 1;
    }
```

**Step 4: Extract inline `channel` dispatch to `dispatch_channel` function**

Move the existing channel dispatch code (main.c lines 964-1050) into a `dispatch_channel()` function in `cli_commands.c`, and add its declaration to `cli_commands.h`. This keeps consistency — all groups dispatch the same way.

**Step 5: Remove old dead dispatch code from main.c**

Delete all the old `else if (strcmp(command, "send") == 0)` etc. blocks that are no longer needed.

**Step 6: Build**

Run: `cd messenger/build && cmake .. && make -j$(nproc)`
Expected: PASS (0 warnings, 0 errors)

**Step 7: Commit**

```bash
git add messenger/cli/main.c messenger/cli/cli_commands.c messenger/cli/cli_commands.h
git commit -m "refactor: replace flat CLI dispatch with group subcommands"
```

---

### Task 5: Refactor `execute_command()` REPL dispatcher in `cli_commands.c`

**Files:**
- Modify: `messenger/cli/cli_commands.c`

**Step 1: Replace the flat dispatch in `execute_command()`**

Replace the entire `if/else if` chain inside `execute_command()` (lines 4483-4703+) with:

```c
    /* Dispatch to group */
    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "?") == 0) {
        cmd_help();
    }
    else if (strcmp(cmd, "quit") == 0 || strcmp(cmd, "exit") == 0 || strcmp(cmd, "q") == 0) {
        free(input);
        return false;
    }
    else if (strcmp(cmd, "identity") == 0) {
        char *subcmd = strtok(NULL, " \t");
        dispatch_identity_repl(engine, subcmd);
    }
    else if (strcmp(cmd, "contact") == 0) {
        char *subcmd = strtok(NULL, " \t");
        dispatch_contact_repl(engine, subcmd);
    }
    else if (strcmp(cmd, "message") == 0) {
        char *subcmd = strtok(NULL, " \t");
        dispatch_message_repl(engine, subcmd);
    }
    else if (strcmp(cmd, "group") == 0) {
        char *subcmd = strtok(NULL, " \t");
        dispatch_group_repl(engine, subcmd);
    }
    else if (strcmp(cmd, "channel") == 0) {
        char *subcmd = strtok(NULL, " \t");
        dispatch_channel_repl(engine, subcmd);
    }
    else if (strcmp(cmd, "wallet") == 0) {
        char *subcmd = strtok(NULL, " \t");
        dispatch_wallet_repl(engine, subcmd);
    }
    else if (strcmp(cmd, "dex") == 0) {
        char *subcmd = strtok(NULL, " \t");
        dispatch_dex_repl(engine, subcmd);
    }
    else if (strcmp(cmd, "network") == 0) {
        char *subcmd = strtok(NULL, " \t");
        dispatch_network_repl(engine, subcmd);
    }
    else if (strcmp(cmd, "version") == 0) {
        char *subcmd = strtok(NULL, " \t");
        dispatch_version_repl(engine, subcmd);
    }
    else if (strcmp(cmd, "sign") == 0) {
        char *subcmd = strtok(NULL, " \t");
        dispatch_sign_repl(engine, subcmd);
    }
    else if (strcmp(cmd, "debug") == 0) {
        char *subcmd = strtok(NULL, " \t");
        dispatch_debug_repl(engine, subcmd);
    }
    else {
        printf("Unknown command group: %s\n", cmd);
        printf("Type 'help' for available groups.\n");
    }
```

**Step 2: Update `cmd_help()` to show groups**

Replace the existing `cmd_help()` function body with grouped help matching the new `print_usage()` style.

**Step 3: Build**

Run: `cd messenger/build && cmake .. && make -j$(nproc)`
Expected: PASS (0 warnings)

**Step 4: Commit**

```bash
git add messenger/cli/cli_commands.c
git commit -m "refactor: replace flat REPL dispatch with group subcommands"
```

---

### Task 6: Build verification and smoke test

**Files:** None (testing only)

**Step 1: Full build**

Run: `cd messenger/build && cmake .. && make -j$(nproc)`
Expected: 0 warnings, 0 errors

**Step 2: Smoke test — help**

Run: `./cli/dna-messenger-cli help`
Expected: Shows group list with descriptions

**Step 3: Smoke test — group help**

Run: `./cli/dna-messenger-cli identity help`
Expected: Shows identity subcommand list

Run: `./cli/dna-messenger-cli wallet help`
Expected: Shows wallet subcommand list

**Step 4: Smoke test — actual command**

Run: `./cli/dna-messenger-cli identity list`
Expected: Lists identities (same output as old `list`)

Run: `./cli/dna-messenger-cli version check`
Expected: Shows version info from DHT

**Step 5: Smoke test — error handling**

Run: `./cli/dna-messenger-cli identity`
Expected: Shows usage with subcommand list (not crash)

Run: `./cli/dna-messenger-cli blah`
Expected: "Unknown command group: blah"

---

### Task 7: Update documentation

**Files:**
- Modify: `messenger/docs/CLI_TESTING.md`

**Step 1: Rewrite CLI_TESTING.md**

Update all command examples from flat format to grouped format:
- `$CLI create alice` → `$CLI identity create alice`
- `$CLI send nox "hello"` → `$CLI message send nox "hello"`
- `$CLI wallets` → `$CLI wallet list`
- `$CLI balance 0` → `$CLI wallet balance 0`
- etc.

Update the Quick Reference section to show groups.
Update all Testing Workflows.

**Step 2: Commit**

```bash
git add messenger/docs/CLI_TESTING.md
git commit -m "docs: update CLI_TESTING.md for subcommand groups"
```

---

### Task 8: Version bump and final commit

**Files:**
- Modify: `messenger/include/dna/version.h`

**Step 1: Bump C library patch version**

This is a refactor of the CLI dispatch — bump PATCH.

**Step 2: Final build verification**

Run: `cd messenger/build && cmake .. && make -j$(nproc)`
Expected: PASS

**Step 3: Commit**

```bash
git add messenger/include/dna/version.h
git commit -m "refactor: CLI subcommand groups (v0.X.Y)"
```

---

## Risk Notes

- **No `cmd_*` signatures change** — all implementations stay untouched
- **No breaking change for Flutter/Android** — CLI is not called from FFI (verified)
- **REPL mode** (`execute_command`) and **single-command mode** (`main.c`) both need updating — easy to forget one
- **`needs_identity` logic** must account for group-level check (e.g., `identity create` doesn't need identity, but `identity whoami` does)
- **`channel` already works** — extract to `dispatch_channel()` for consistency but don't break existing behavior
