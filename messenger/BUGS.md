# DNA Messenger - Known Bugs

Bug reports for Claude to fix. Format: `- [ ] Description (priority)`

Priorities: `P1` = Critical, `P2` = High, `P3` = Medium, `P4` = Low

---

## Open Bugs

- [ ] Wallet balance formatting inconsistent: SOL extra zeros, USDT plain "0", TRX shows symbol after amount (P3)
- [ ] DHT status always shows "Disconnected" in menu drawer even when connected (P2)
- [ ] Emoji picker overflows on full-sized window - RenderFlex overflow in search view (P3)
- [ ] Emoji picker shows only ~4 emojis on large screens - should scale with window size (P3)
- [ ] Emoji picker search button turns box gray - looks broken even though it works (P4)
- [ ] Messages not synced between devices - need cross-platform message sync via DHT (P2)
- [ ] Remove Contact button in chat doesn't work (P3)
- [ ] Send CPUNK in chat fails - says contact has no Backbone wallet even when they do (P2)
- [ ] Show QR Code button in chat doesn't show anything (P4)
- [ ] Take a Selfie button doesn't work on Linux desktop (P4)
- [ ] Profile wallet address fields redundant - app auto-generates wallets from seed (P4)
- [ ] Social media icons missing for X, GitHub, Instagram, LinkedIn, Google in profile editor (P4)


## Fixed Bugs

- [x] Add contact: show avatar in search result instead of initials (v0.2.42)
- [x] Message loss when sending fast - DHT putSigned was async (v0.2.38)
- [x] Message UI refresh storm - per-message refresh replaced optimistic UI (v0.2.39)
- [x] Slow message sending - blocking DHT wait replaced with local outbox cache (v0.2.40)
