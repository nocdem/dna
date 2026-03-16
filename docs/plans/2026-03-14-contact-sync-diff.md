# Contact Sync: REPLACE → DIFF Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the "DELETE ALL + re-INSERT" contact sync with a diff-based approach that preserves all local metadata (nicknames, DM sync timestamps, salts) without explicit save/restore.

**Architecture:** Instead of clearing the contacts table and re-inserting from DHT, compute the diff between local and DHT lists: remove contacts not in DHT, add contacts only in DHT, leave existing contacts untouched. Salt updates still applied for contacts present in both lists (DHT salt may have been rotated on another device).

**Tech Stack:** C, SQLite, existing `contacts_db` API

---

### Background

Current flow in `messenger/messenger/contacts.c` → `messenger_sync_contacts_from_dht()`:
1. Fetch contact list from DHT
2. `contacts_db_list()` — snapshot local contacts
3. Save dm_sync_timestamps in separate array (recent fix)
4. `contacts_db_clear_all()` — DELETE all rows
5. `contacts_db_add()` for each DHT contact
6. Restore salts from DHT backup
7. Restore nicknames from snapshot
8. Restore dm_sync_timestamps from snapshot

**Problems:**
- Every future local-only field must be manually saved/restored (fragile)
- Unnecessary DB churn: 5 DELETEs + 5 INSERTs when nothing changed
- Ordering/indexing of snapshot array must match (error-prone)

**New flow:**
1. Fetch contact list from DHT
2. `contacts_db_list()` — snapshot local contacts
3. Compute diff:
   - `to_remove` = local contacts NOT in DHT list
   - `to_add` = DHT contacts NOT in local list
   - `existing` = contacts in BOTH (update salt only)
4. `contacts_db_remove()` for each `to_remove`
5. `contacts_db_add()` for each `to_add` (with salt)
6. `contacts_db_set_salt()` for each `existing` (if DHT has salt)
7. Done — nicknames, dm_sync_timestamps, everything untouched

---

### Task 1: Replace REPLACE sync with DIFF sync

**Files:**
- Modify: `messenger/messenger/contacts.c:277-359` (the REPLACE sync block)

**Step 1: Replace the sync block**

Replace everything from the `// DHT-AUTHORITATIVE` comment (line 277) through `if (local_list) contacts_db_free_list(local_list);` (line 359) with:

```c
    // DHT-AUTHORITATIVE DIFF SYNC: Only add/remove what changed
    QGP_LOG_INFO(LOG_TAG, "DIFF sync: DHT has %zu contacts (local had %d)\n", count, local_count);

    // Snapshot local contacts for diff
    contact_list_t *local_list = NULL;
    contacts_db_list(&local_list);

    // Phase 1: Remove contacts that are in local but NOT in DHT
    size_t removed = 0;
    if (local_list && local_list->count > 0) {
        for (size_t i = 0; i < local_list->count; i++) {
            const char *local_id = local_list->contacts[i].identity;
            bool found_in_dht = false;
            for (size_t j = 0; j < count; j++) {
                if (contacts[j] && strcmp(local_id, contacts[j]) == 0) {
                    found_in_dht = true;
                    break;
                }
            }
            if (!found_in_dht) {
                contacts_db_remove(local_id);
                removed++;
            }
        }
    }

    // Phase 2: Add contacts that are in DHT but NOT in local, update salts for existing
    size_t added = 0;
    size_t salts_updated = 0;
    for (size_t i = 0; i < count; i++) {
        if (!is_valid_fingerprint(contacts[i])) {
            QGP_LOG_WARN(LOG_TAG, "DIFF: Skipping invalid fingerprint from DHT (len=%zu)\n",
                         contacts[i] ? strlen(contacts[i]) : 0);
            continue;
        }

        if (contacts_db_exists(contacts[i])) {
            // Already exists — just update salt if DHT has one
            if (salts && salts[i]) {
                if (contacts_db_set_salt(contacts[i], salts[i]) == 0) {
                    salts_updated++;
                }
            }
        } else {
            // New contact from DHT — add it
            if (contacts_db_add(contacts[i], NULL) == 0) {
                added++;
                if (salts && salts[i]) {
                    contacts_db_set_salt(contacts[i], salts[i]);
                }
            } else {
                QGP_LOG_ERROR(LOG_TAG, "Failed to add contact '%s'\n", contacts[i]);
            }
        }
    }

    if (local_list) contacts_db_free_list(local_list);
```

**Step 2: Update the log line and cleanup**

Replace the final summary log:

```c
    dht_contactlist_free_contacts(contacts, count);
    dht_contactlist_free_salts(salts, count);

    QGP_LOG_INFO(LOG_TAG, "DIFF sync complete: +%zu added, -%zu removed, %zu salt updates (DHT=%zu, local was %d)\n",
           added, removed, salts_updated, count, local_count);
    return 0;
```

**Step 3: Remove dead code**

Delete the `saved_dm_timestamps` allocation, the `RESTORE LOCAL-ONLY METADATA` block, and `free(saved_dm_timestamps)` — none of this is needed anymore since we never clear contacts.

**Step 4: Build**

```bash
cd /opt/dna/messenger/build && make -j$(nproc)
```

Expected: Clean build, zero warnings, zero errors.

**Step 5: Commit**

```bash
git add messenger/messenger/contacts.c
git commit -m "refactor(contacts): replace DELETE+reinsert sync with diff-based sync

Preserves all local metadata (nicknames, dm_sync_timestamps) without
explicit save/restore by only adding/removing what actually changed."
```

---

### Task 2: Verify no regressions

**Files:**
- Read: `messenger/messenger/contacts.c` (verify final state)

**Step 1: Read and verify the complete sync function**

Ensure:
- Invariant guard (count==0 && local>0 → publish local) still present
- `contacts_db_remove()` called for removed contacts
- `contacts_db_add()` only for genuinely new contacts
- Salt update for existing contacts
- No references to `saved_dm_timestamps` or `contacts_db_clear_all()` remain
- Error paths clean (no leaked memory)

**Step 2: Build**

```bash
cd /opt/dna/messenger/build && make -j$(nproc)
```

**Step 3: Run tests**

```bash
cd /opt/dna/messenger/build && ctest --output-on-failure
```

---

### Risk Assessment

| Risk | Mitigation |
|------|-----------|
| O(N×M) loop for diff (N=local, M=DHT) | Max ~50 contacts, negligible |
| Salt rotation on another device not picked up | Explicit salt update in Phase 2 for existing contacts |
| `contacts_db_exists()` extra DB query per contact | Already used in current code, negligible cost |
| Edge case: contact removed from DHT but has unread messages | Same behavior as current code — messages still in message DB |
