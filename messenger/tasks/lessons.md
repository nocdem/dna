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

## Flutter / Dart
- Use `DnaLogger` instead of `print()` - print is expensive on Android logcat
- Riverpod providers should preserve state during engine lifecycle transitions
- Only animate truly new messages, not history loads

## Documentation
- Design proposals must be clearly labeled - don't mix with current-state docs
- Version numbers in docs go stale fast - always verify against source files
- Function reference docs must be updated when adding new public APIs
