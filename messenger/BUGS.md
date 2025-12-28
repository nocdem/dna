# DNA Messenger - Known Bugs

Bug reports for Claude to fix. Format: `- [ ] Description (priority)`

Priorities: `P1` = Critical, `P2` = High, `P3` = Medium, `P4` = Low

---

## Open Bugs

- [ ] DHT status always disconnected (P2)
- [ ] Message sync between devices (P2)
- [ ] Send CPUNK fails - no Backbone wallet (P2)
- [ ] Wallet balance formatting (SOL/USDT/TRX) (P3)
- [ ] Emoji picker overflow on fullscreen (P3)
- [ ] Emoji picker shows only ~4 emojis (P3)
- [ ] Remove Contact button broken (P3)
- [ ] Emoji picker search turns gray (P4)
- [ ] Show QR Code does nothing (P4)
- [ ] Camera doesn't work on Linux (P4)
- [ ] Profile wallet fields redundant (P4)
- [ ] Social media icons missing (P4)


## Fixed Bugs

- [x] DHT "Node not running" errors - dht_singleton_get returned stopped context during reinit (v0.2.61)
- [x] DHT "Broken promise" errors - operations started before DHT connected after reinit (v0.2.60)
- [x] Use-after-free in messenger_p2p_subscribe_to_contacts - accessed contacts->count after free (v0.2.59)
- [x] Heap-buffer-overflow in keyserver_profiles.c - strstr on non-null-terminated buffer (v0.2.59)
- [x] Memory leak in dht_identity - owned_identity not freed on context cleanup (v0.2.59)
- [x] Add contact: show avatar in search result instead of initials (v0.2.42)
- [x] Message loss when sending fast - DHT putSigned was async (v0.2.38)
- [x] Message UI refresh storm - per-message refresh replaced optimistic UI (v0.2.39)
- [x] Slow message sending - blocking DHT wait replaced with local outbox cache (v0.2.40)
