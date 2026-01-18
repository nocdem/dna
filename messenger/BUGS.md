# DNA Messenger - Known Bugs

Bug reports for Claude to fix. Format: `- [ ] Description (priority)`

Priorities: `P1` = Critical, `P2` = High, `P3` = Medium, `P4` = Low

**Debug Categories:**
- `[CLI]` = Can debug via CLI tool (`dna-messenger-cli`)
- `[FLUTTER]` = Requires human testing in Flutter app
- `[MIXED]` = Partially CLI-debuggable, may need Flutter verification

---

## Open Bugs

- [ ] **[FLUTTER] P4 - Group chat send icon doesn't match normal chat** - The send button icon in group chat screen is different from the one used in 1:1 chat screens. Should be consistent across all chat types.

- [ ] **[FLUTTER] P3 - Background notification toggle doesn't re-request permissions** - When user disables then re-enables "Background Notifications" in settings, it doesn't prompt for notification permissions again. Should call `requestNotificationPermission()` when toggling ON.

- [ ] **[FLUTTER] P2 - Auto sync toggle freezes app** - Clicking the "Auto Sync" switch in settings freezes the entire app for ~5 seconds while backup runs synchronously. Should run async with loading indicator.

- [ ] **[FLUTTER] P2 - Sync Now button freezes app** - The manual "Sync Now" button freezes the app during sync with no feedback. Should show loading indicator and toast on success/failure.

- [ ] **[FLUTTER] P2 - Backup Messages button freezes app** - In the backup messages modal, clicking backup freezes the entire app while backup runs synchronously. Should show loading indicator in modal and run async.

- [ ] **[FLUTTER] P3 - Avatar not restored when reinstalling from scratch** - After fresh install and restoring identity from seed phrase, avatar is not correctly restored from DHT. Profile data (name, etc.) may restore but avatar image is missing or not displayed.

- [x] **[CLI] P2 - DHT PUT_SIGNED high failure rate** - Logs showed ~77% failure rate (986 failed vs 298 stored). Error: "PUT_SIGNED: Failed to store on any node". **Root cause:** Burst flooding from chunked operations (10-50 rapid PUTs per action) overwhelming DHT nodes. **Fix:** Added 100ms delay between chunk PUTs in `dht_chunked.c` to rate-limit operations. (v0.4.23)

- [ ] **[FLUTTER] P3 - Presence status not updating in open chat** - When viewing a chat, the contact's online/offline status doesn't update in real-time. User has to close the chat to see updated presence in contacts list. The chat header should reflect live presence changes.

- [ ] **[FLUTTER] P2 - Chat window causes constant image flashing** - Sent/received images in chat flash repeatedly. Chat window implementation needs refactoring to avoid unnecessary rebuilds. Consider using `const` widgets, `RepaintBoundary`, or caching decoded images.

---

## Feature Requests

- [ ] **[CLI] P2 - DHT key derivation leaks communication metadata** - Current outbox/watermark keys are deterministic: `SHA3-512(sender:outbox:recipient)`. A third party who knows both fingerprints can calculate these keys and monitor DHT to detect if/when two parties communicate (timing, frequency, direction). Message content remains encrypted, but existence of communication is leaked. **Proposed fix:** Add per-contact random 32-byte salt exchanged during contact establishment. New key format: `SHA3-512(salt:sender:outbox:recipient)`. Third parties cannot calculate keys without the salt. **See:** [docs/PRIVACY_DHT_KEY_DERIVATION.md](docs/PRIVACY_DHT_KEY_DERIVATION.md) for full analysis and implementation plan.

## Fixed Bugs

- [x] **[MIXED] P1 - Message status stuck on clock icon until app restart** - Messages were delivered (watermark updates DB to DELIVERED) but Flutter UI kept showing clock icon. **Root cause:** Watermark key mismatch - `dht_publish_watermark_async()` and `dht_get_watermark()` used raw string key while `dht_listen_watermark()` used SHA3-512 hash. Publisher and listener were on different DHT keys. **Fix:** v0.4.23 fixed publish to use SHA3-512, v0.4.24 fixed get to use SHA3-512. Also added MESSAGE_DELIVERED event handler in Flutter and fixed event data type (contactFingerprint instead of messageId). (v0.4.24, v0.99.114)

- [x] **[MIXED] P2 - DHT listeners not working on desktop** - Contact request listener, outbox listeners, and presence listeners didn't fire on desktop (Linux/Windows). Worked on Android. Three bugs: (1) Identity load checked `p2p_enabled` before starting listeners, but P2P transport often fails on desktop while DHT works fine - fixed by removing check (v0.3.156). (2) When contact count=0, function returned early without starting contact request listener - users with no contacts couldn't receive requests - fixed by starting contact_req listener before early return (v0.3.157). (3) Flutter event handler refreshed contacts before auto-approval completed - fixed by waiting for contactRequestsProvider fetch to complete before refreshing (v0.99.98).

- [x] **[MIXED] P2 - DHT listeners don't survive network changes (WiFi→mobile)** - After network change, engine-level arrays got out of sync with DHT layer. Fixed by: running listener setup on background thread (avoids deadlock), adding 5s timeout to `dht_listen_ex()`, cancelling contact request listener in setup thread, refreshing contacts on contact request event (auto-approval for reciprocal requests), increasing `DHT_MAX_LISTENERS` to 1024, removing 60s contact request polling (use DHT listener instead). (v0.3.155)

- [x] **[FLUTTER] P2 - Unread count stops working after opening/closing chat** - `selectedContactProvider` was not being reset to null when closing chat via back navigation. This caused `isChatOpen=true` even when chat was closed, skipping `incrementCount()`. Fixed by resetting to null in ChatScreen's `dispose()`. (v0.99.97)

- [x] **[CLI] P1 - Heap-buffer-overflow in offline message JSON parsing** - `messenger_p2p.c:941` called `json_tokener_parse()` on plaintext buffer from `dna_decrypt_message_raw()` without null-termination. When decrypted content was small (e.g., 4 bytes from corrupted message), ASAN detected read past buffer. Fixed by realloc+null-terminate before parsing. (v0.3.139)

- [x] **[FLUTTER] P2 - CPUNK sending broken in chat window** - Fixed error mapping in C code (insufficient balance was incorrectly returned as "Network error"). Improved Flutter dialog UX: errors now display in-dialog instead of snackbar, added pre-send balance validation, dialog stays open on error. (v0.3.118, v0.99.68)

- [x] **[FLUTTER] P3 - Contacts briefly show as online during DHT fetch** - Caused by unnecessary `_ref.invalidate(contactsProvider)` calls triggering full rebuilds with `_updatePresenceInBackground()`. Fixed by removing invalidate from presence polling (every 30s) since presence updates already come through via ContactOnline/ContactOffline events handled by `updateContactStatus()`. (v0.99.61)

- [x] **[FLUTTER] P4 - Full contact list refresh on single message** - Comment said "refresh contacts to update last message preview" but contact tiles don't show message previews - only avatar, name, online status, and unread count. Removed unnecessary `_ref.invalidate(contactsProvider)` from MessageReceivedEvent handler. Unread counts already updated via `incrementCount()`. (v0.99.61)

- [x] **[FLUTTER] P3 - Contacts show lastSeen=1970-01-01** - Presence cache was in-memory only, lost on app restart. Added `last_seen` column to contacts table, presence updates now persist to database. On startup, fallback to database value when cache is empty. (v0.3.110)

- [x] **[CLI] P2 - TRON transactions fail on Android with SSL error** - `trx_tx.c` and `trx_trc20.c` were missing `CURLOPT_CAINFO` configuration. Linux uses system certs automatically but Android requires explicit CA bundle path. (v0.3.107)

- [x] **[FLUTTER] P3 - Rapid message sending delays message delivery** - When sending multiple messages quickly, receiver would trigger parallel `checkOfflineMessages()` calls causing race conditions. Fixed by debouncing `OutboxUpdatedEvent` with 400ms delay to coalesce rapid events into single DHT fetch. (v0.99.57)

- [x] **[FLUTTER] P2 - Presence system has duplicate calls and ignores app lifecycle** - Fixed by adding pausePolling()/resumePolling() to EventHandler that lifecycle_observer calls on app pause/resume. Timers now properly stop in background. (v0.99.28)


- [x] **[MIXED] Profile shows "Anonymous" after identity creation** - `dna_handle_get_profile()` was missing copy of display_name/registered_name, location, website fields. Added fallback logic matching `dna_handle_lookup_profile()`. Flutter provider cleanup (5+ redundant providers) still recommended as separate task. (v0.3.61)

- [x] Log sharing: Works on mobile but didn't work on PC (share_plus not supported). PC now shows native file save dialog using `file_picker` package. (v0.99.17)

- [x] Avatar cropping: Add Telegram-style circular crop/pan/zoom when selecting avatar. Increased size from 64x64 to 128x128. Using `crop_your_image` package for cross-platform support. (v0.99.16)

- [x] Profile not loaded after creating identity on Android - need app restart - DHT propagation delay, fixed by caching locally after publish (v0.3.56). Additional fix: profile_cache_close() before identity deletion to release stale file handles (v0.3.58). Final fix: lazy initialization of profile cache - database auto-reinitializes after close (v0.3.59)

- [x] Profile editor floating label clipped by dropdown header - added top padding to ExpansionTile content (v0.99.13)
- [x] Double free crash - Dilithium key delete tried to free stack-allocated struct address, fixed to only free internal data buffer (v0.3.39)
- [x] Heap-allocate events for async Dart callbacks - dna_free_event added (v0.3.38)
- [x] Profile editor input field icons misaligned - wrapped FaIcon in SizedBox with Center for proper alignment (v0.99.12)
- [x] AddressSanitizer: ~4KB memory leak in Dilithium key cleanup - `dap_return_if_pass` macro was inverted, fixed in `dap_crypto_common.h` (v0.3.37)
- [x] AddressSanitizer: 16 byte leak in `contacts_db_list()` - missing free in `transport_offline.c` when count == 0 (v0.3.37)

- [x] Show QR Code button in chat doesn't show anything - implemented QR dialog with contact fingerprint (v0.3.34)
- [x] Contact requests show fingerprint instead of username - _RequestTile now uses cached profile displayName fallback (v0.3.32)
- [x] Contacts list shows fingerprint even when registered_name exists - C code now checks identity->registered_name after display_name (v0.3.31)
- [x] Contacts list and chat header show fingerprint instead of username - Flutter now uses cached profile displayName as fallback (v0.3.30)
- [x] Profile dialog shows fingerprint instead of username - fallback to registered_name when display_name empty (v0.3.28)
- [x] Contacts list shows fingerprint instead of username - add fallback chain: DHT profile -> keyserver cache -> stored notes -> fingerprint (v0.3.27)
- [x] Contact requests show only fingerprint, not username - use keyserver_cache_get_name instead of unreliable name_cache (v0.3.26)
- [x] Menu drawer: avatar and name should be on same line - changed to Row layout (v0.3.25)
- [x] Menu drawer: profile info misaligned to right - added SizedBox width constraint (v0.3.24)
- [x] Profile fields (display_name, location, website) not saved to DHT - internal dna_profile_data_t struct was incomplete, removed and now using dna_profile_t everywhere (v0.3.23)
- [x] Avatar disappears after editing profile settings - cache update now happens directly after save instead of fetching from DHT (v0.3.23)
- [x] Seed phrase screen Continue button not full width (v0.99.1)
- [x] Restore flow shows "Creating your identity" instead of "Loading identity" for returning users (v0.3.22)
- [x] Emoji picker search button turns box gray - fixed with SearchViewConfig (v0.2.119)
- [x] Social media icons missing - added Font Awesome icons for all social fields (v0.2.125)
- [x] Take a Selfie button doesn't work on desktop - hidden, opens gallery directly (v0.2.124)
- [x] Emoji picker overflows on full-sized window - responsive sizing + SearchViewConfig (v0.2.119)
- [x] Emoji picker shows only ~4 emojis on large screens - dynamic columns based on width (v0.2.119)
- [x] Wallet balance formatting inconsistent: SOL extra zeros, USDT plain "0", TRX shows symbol after amount (v0.2.118)
- [x] Remove Contact button in chat doesn't work - implement confirmation dialog (v0.2.110)
- [x] DHT push notifications not working - use event-based listeners (v0.2.111)
- [x] Contact requests reappear after restart - skip if already a contact (v0.2.108)
- [x] Messages not synced between devices - message backup/restore via DHT (v0.2.106)
- [x] Username/avatar not showing on identity selection - use lookupProfile (single DHT call) (v0.2.93)
- [x] Send CPUNK fails "no Backbone wallet" - derive address from Dilithium pubkey (v0.2.89)
- [x] DHT status always shows "Disconnected" in menu drawer - sync status on event handler init (v0.2.88)
- [x] DHT operations during reinit - dht_singleton_get now waits for DHT to be ready (v0.2.62)
- [x] DHT "Broken promise" errors - operations started before DHT connected after reinit (v0.2.60)
- [x] Use-after-free in messenger_p2p_subscribe_to_contacts - accessed contacts->count after free (v0.2.59, function removed v0.2.112)
- [x] Heap-buffer-overflow in keyserver_profiles.c - strstr on non-null-terminated buffer (v0.2.59)
- [x] Memory leak in dht_identity - owned_identity not freed on context cleanup (v0.2.59)
- [x] Add contact: show avatar in search result instead of initials (v0.2.42)
- [x] Message loss when sending fast - DHT putSigned was async (v0.2.38)
- [x] Message UI refresh storm - per-message refresh replaced optimistic UI (v0.2.39)
- [x] Slow message sending - blocking DHT wait replaced with local outbox cache (v0.2.40)
