# Lessons Learned

*Accumulated patterns and self-corrections from development sessions.*

---

## Build & Compilation
- Always run full build output (no `tail` or `grep` filtering) to catch all warnings
- Windows `long` is 32-bit: always cast `uint64_t` to `(unsigned long long)` for `%llu`
- `winsock2.h` MUST be included before `windows.h` on Windows

## Android / Mobile
- Android lifecycle is complex: engine destroy/create is safer than pause/resume
- ForegroundService type must be `remoteMessaging`, not `dataSync`
- JNI sync calls must check shutdown flag to prevent hangs
- Never use `pthread_timedjoin_np` - not portable (use `nanosleep` polling instead)

## DHT / Network
- DHT chunk PUT needs generous timeouts (60s+) for large values
- Daily bucket pattern reduces DHT lookups for offline sync
- Feed system should use chunked DHT pattern for scalability
- **Bootstrap cache can contain stale nodes from old protocol versions** — always fallback to hardcoded nodes when cached nodes fail to connect
- When debugging "network error" in Flutter but CLI works: check the logs first (`dna.log`), root cause is usually in C layer not Flutter

## Flutter / Dart
- Use `DnaLogger` instead of `print()` - print is expensive on Android logcat
- Riverpod providers should preserve state during engine lifecycle transitions
- Only animate truly new messages, not history loads

## Documentation
- Design proposals must be clearly labeled - don't mix with current-state docs
- Version numbers in docs go stale fast - always verify against source files
- Function reference docs must be updated when adding new public APIs

## Process / Self-Discipline
- **ALWAYS update lessons.md and MEMORY.md after fixing a bug or learning something** — don't wait for user to remind you
- After every fix: update lessons.md with the pattern, update MEMORY.md with current state
- **ALWAYS push to BOTH repos in a single command**: `git push origin main && git push gitlab main` — NEVER push to just one
