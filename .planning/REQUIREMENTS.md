# Requirements: DNA Connect Stabilization

**Defined:** 2026-04-12
**Core Value:** Basic flows — contacts, messaging, token sending — must work without errors or weirdness

## v1 Requirements

Requirements for stabilization release. Each maps to roadmap phases.

### Security

- [ ] **SEC-01**: Fix contact request auto-approval bypass — attacker bypasses user approval with crafted message
- [ ] **SEC-02**: Fix key file size validation in qgp_key_load — accepts attacker-controlled sizes for malloc
- [ ] **SEC-03**: Fix QR auth JSON injection — string interpolation allows injection in JSON construction
- [ ] **SEC-04**: Fix GEK thread safety race condition — race on global KEM key pointers
- [ ] **SEC-05**: Fix detached backup thread use-after-free — engine destroy while backup threads running
- [ ] **SEC-06**: Zero mnemonic before free — seed phrase persists in freed heap memory
- [ ] **SEC-07**: Replace debugPrint leaking auth data in release — session IDs visible in logcat on Android
- [ ] **SEC-08**: Fix app lock bypass via SharedPreferences — lockout counters in unencrypted storage
- [ ] **SEC-09**: Fix clipboard seed exposure — 30s clipboard window, no cleanup on app kill
- [ ] **SEC-10**: Add screen capture protection on seed export — no FLAG_SECURE when showing seed phrase

### Thread Safety

- [ ] **THR-01**: Fix outbox cache thread safety — static globals without mutex in offline queue
- [ ] **THR-02**: Fix nodus init thread safety — 12+ static globals without mutex
- [ ] **THR-03**: Fix/document task queue concurrent submission — MPSC queue lacks CAS, relies on single-producer assumption

### Core Flow Bugs

- [ ] **CORE-01**: Fix feed categories showing SHA256 hashes instead of names — 64-char hex displayed instead of category names
- [ ] **CORE-02**: Fix background notification permission toggle — toggle ON doesn't re-request permissions
- [ ] **CORE-03**: Fix camera permission after reinstall — QR scanner doesn't request camera on fresh install
- [x] **CORE-04**: Complete DHT metadata privacy salt migration — deterministic outbox keys leak communication patterns
- [x] **CORE-05**: Fix name registration failure — registration doesn't go through and user gets locked out of changing name afterwards (C engine + Flutter, needs investigation)

### Unsafe C Patterns

- [ ] **SAFE-01**: Replace strcpy/sprintf with safe alternatives across codebase — 17+ strcpy, 20+ sprintf with fixed-size stack buffers

## v2 Requirements

Deferred to future release. Tracked but not in current roadmap.

### Test Coverage

- **TEST-01**: Add engine module unit tests for 18 engine modules
- **TEST-02**: Add concurrency tests to validate thread safety fixes
- **TEST-03**: Add Flutter provider/FFI tests
- **TEST-04**: Expand DNAC test coverage

### Code Quality

- **QUAL-01**: Remove 1607 lines of disabled channel code
- **QUAL-02**: Fix Windows platform gaps (RTT measurement, etc.)
- **QUAL-03**: Add CI test execution (ctest in pipeline)

### Data Integrity

- **DATA-01**: Re-enable BSC transaction history with new API
- **DATA-02**: Implement DNAC memo field (currently silently dropped)
- **DATA-03**: Add task queue back-pressure feedback to Flutter

## Out of Scope

| Feature | Reason |
|---------|--------|
| New features | Stabilization only — scope creep is the #1 stabilization killer |
| Architecture rewrites | RC with real users — fix within existing patterns |
| Performance optimization | Unless causing visible bugs |
| Nodus server changes | Server is stable; focus is the client |
| iOS port | Separate milestone entirely |
| Breaking changes (message format v0.09) | RC with real users, no migration path yet |
| Token-to-ETH reverse swap | New feature, not a bug fix |
| Comprehensive file splitting | Tech debt, not bugs — risks regressions mid-stabilization |

## Traceability

Which phases cover which requirements. Updated during roadmap creation.

| Requirement | Phase | Status |
|-------------|-------|--------|
| SEC-01 | Phase 1 | Pending |
| SEC-02 | Phase 1 | Pending |
| SEC-03 | Phase 4 | Pending |
| SEC-04 | Phase 2 | Pending |
| SEC-05 | Phase 2 | Pending |
| SEC-06 | Phase 1 | Pending |
| SEC-07 | Phase 4 | Pending |
| SEC-08 | Phase 4 | Pending |
| SEC-09 | Phase 5 | Pending |
| SEC-10 | Phase 5 | Pending |
| THR-01 | Phase 2 | Pending |
| THR-02 | Phase 2 | Pending |
| THR-03 | Phase 2 | Pending |
| CORE-01 | Phase 7 | Pending |
| CORE-02 | Phase 7 | Pending |
| CORE-03 | Phase 7 | Pending |
| CORE-04 | Phase 6 | Complete |
| CORE-05 | Phase 6 | Complete |
| SAFE-01 | Phase 3 | Pending |

**Coverage:**
- v1 requirements: 19 total
- Mapped to phases: 19
- Unmapped: 0

---
*Requirements defined: 2026-04-12*
*Last updated: 2026-04-12 after roadmap creation*
