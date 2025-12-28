# DNA Messenger - Known Bugs

Bug reports for Claude to fix. Format: `- [ ] Description (priority)`

Priorities: `P1` = Critical, `P2` = High, `P3` = Medium, `P4` = Low

---

## Open Bugs

- [ ] Wallet balance formatting inconsistent: SOL extra zeros, USDT plain "0", TRX shows symbol after amount (P3)
- [ ] Emoji picker overflows on full-sized window - RenderFlex overflow in search view (P3)
- [ ] Emoji picker shows only ~4 emojis on large screens - should scale with window size (P3)
- [ ] Emoji picker search button turns box gray - looks broken even though it works (P4)
- [ ] Show QR Code button in chat doesn't show anything (P4)
- [ ] Take a Selfie button doesn't work on Linux desktop (P4)
- [ ] Profile wallet address fields redundant - app auto-generates wallets from seed (P4)
- [ ] Social media icons missing for X, GitHub, Instagram, LinkedIn, Google in profile editor (P4)


## Fixed Bugs

- [x] Remove Contact button in chat doesn't work - implement confirmation dialog (v0.2.110)
- [x] DHT push notifications not working - resubscribe to contacts when DHT connects (v0.2.109)
- [x] Contact requests reappear after restart - skip if already a contact (v0.2.108)
- [x] Messages not synced between devices - message backup/restore via DHT (v0.2.106)
- [x] Username/avatar not showing on identity selection - use lookupProfile (single DHT call) (v0.2.93)
- [x] Send CPUNK fails "no Backbone wallet" - derive address from Dilithium pubkey (v0.2.89)
- [x] DHT status always shows "Disconnected" in menu drawer - sync status on event handler init (v0.2.88)
- [x] DHT operations during reinit - dht_singleton_get now waits for DHT to be ready (v0.2.62)
- [x] DHT "Broken promise" errors - operations started before DHT connected after reinit (v0.2.60)
- [x] Use-after-free in messenger_p2p_subscribe_to_contacts - accessed contacts->count after free (v0.2.59)
- [x] Heap-buffer-overflow in keyserver_profiles.c - strstr on non-null-terminated buffer (v0.2.59)
- [x] Memory leak in dht_identity - owned_identity not freed on context cleanup (v0.2.59)
- [x] Add contact: show avatar in search result instead of initials (v0.2.42)
- [x] Message loss when sending fast - DHT putSigned was async (v0.2.38)
- [x] Message UI refresh storm - per-message refresh replaced optimistic UI (v0.2.39)
- [x] Slow message sending - blocking DHT wait replaced with local outbox cache (v0.2.40)
