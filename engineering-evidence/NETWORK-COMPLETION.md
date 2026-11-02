# Wallet network integration checkpoint

Baseline: nocdem/dna `5eb8dc724679b84fb31d22116e381df71b747a3b` (0.1.155).
Working tree only: no release, push, merge, deployment or transaction submission.

## Current readiness — frozen candidate, 2026-11-02 09:45 UTC

Earlier checkpoints below are chronological evidence, not current gates.

| Network | Implemented and verified | Remaining before complete support |
|---|---|---|
| ALGO | Mainnet trusted extension and Web candidate send enabled after independently reviewed authenticated per-attempt ownership fix. Official Falcon KATs, native signature/serialization oracles, synthetic read-only simulation authentication; guarded confirmation, durable activity, historical inclusion/expiry reconciliation. | Testnet protocol unsupported; no funded admission or device QA. The final 09:43 minified extension package passed static checks. |
| SOQ | Mainnet Web and trusted extension candidate send enabled. Native node transaction/signature vectors, mature node-verified input selection, fee review, durable outpoints, ciphertext-only known-no-POST recovery and explicit same-byte replay. Independent integrated review passed. | Bounded provider-reported native account history is integrated; confidential/mixed/missing rows are excluded, not a complete scan. No funded admission/device QA. Public history probe outcome uncertain after denied wait; no retry. |
| CKB | Full restricted Molecule builder, SLH signer, fee/preflight and isolated review controller. Actual deployed lock VM accepts synthetic transaction and rejects signature/output tampering; native message oracle passes. | Mainnet trusted extension candidate enabled. Durable holder/recovery/status, bounded history and full-format recipient expansion independently reviewed. Canonical full-format Bech32m recipients now supported (not legacy short addresses); quantum empty-data/no-type/non-cellbase inputs. Same-tip preflight can fail transiently. |
| QTC | Full native P2MR builder, signing, fee/preflight and isolated review controller. Pinned native verification plus isolated v0.2.5 regtest testmempoolaccept accepts synthetic transaction; tamper controls reject. Transparent partial history wired. | Mainnet trusted extension candidate enabled after independent structured-UTXO safety review and real trusted-port mock integration. Mandatory raw retrieval is not part of this explicit design; denied /hex route not retried. Fixed provider assumptions,8-input/64KiB bound and uncertainty holds retained. Native P2MR recipient subset only; later source pin differs from tested release. |
| Verona XION | Limited native MsgSend history, independent protobuf/signature fixtures, account preflight, explicit-fee/gas controller, native CheckTx and timeout-boundary oracles, height-pinned guarded lifecycle. | Mainnet trusted extension candidate enabled after exact deployed-source native CheckTx oracle, uint64-account boundary, height-pinned state and durable unknown-outcome timeout lifecycle review. Explicit fee/gas is not a live quote; testnet/Web remain off. Denied fee endpoints not retried. No public signed admission. |
| Splendor SPLD | Official Go v1.2.2 validates our signed envelope/hash. Native history, fee/nonce review, encrypted activity, known-no-POST cancellation and explicit same-byte recovery. Trusted extension routing now implemented. | Trusted extension mainnet candidate enabled after independent routing review and38/38 affected tests. Testnet stays off. Web plumbing tested but gate off because official status endpoint lacks browser ACAO. No live transaction admission/device QA. |
| Asentum ASE | Testnet-only SDK-exact SSZ/BLAKE3/signature, explicit fee-cap controller, finalized receipt reconciliation, encrypted guarded holder and exact-byte recovery. Independent bounded review passed. | Trusted extension testnet candidate enabled after bounded review and capability/RPC isolation tests. Web transport CORS verified and testnet candidate enabled after19/19 bounded review and capability tests. Independent indexed history identity unbound; no invented mainnet or prices. No live admission. |
| Tidecoin TDC | Native legacy Falcon512 oracle, exact transaction/sighash codec, wallet bridge, upstream CheckTransaction/IsStandardTx/VerifyScript acceptance and mutation controls, isolated preflight/controller. No production provider. | Gate off. Official explorer403 blocks usable public balance/history/UTXO transport. Native consensus/script/policy and isolated authenticated-prevout/controller checks pass; production provider remains unavailable. Post-handoff isolated encrypted holder, cancellation proof, exact-byte recovery and cross-session lifecycle tests now pass; it is still unregistered and not a live transport. No guessed providers. |

## Post-handoff IXIOS addition (2026-11-02)

Owner added IXIOS after the immutable seven-network handoff. It is distinct from XION. Trusted extension mainnet code candidate now includes native ML-DSA-87 legacy transfers, 48-byte address identity, fixed genesis plus chain1/Aegis verification, source-native1,000 gas and an explicit atomic gas-price cap. Exact pinned Go codec/signature vectors and native ApplyTransaction admission9/9 pass. The initial Ethereum-style21,000 assumption was corrected before this candidate: source-floor fixture fee is93 IXIOS at1,000 gas, not the1953 IXIOS upfront cap of a21,000-limit transaction.

Encrypted attempt-bound holds, no-exposure cancellation proof, durable terminal barriers, exact-byte user-reviewed recovery and bounded recent native history are reviewed. Runtime quote/identity failures remain fail-closed. There is no live funded acceptance or device QA. Fresh batch RPC403 and a separately issued later single quote are recorded chronologically; denied access is not claimed resolved and all live probes stopped. Coinstore IXIOSUSDT identity is official, but recent-trade GET403 and USDT/USD distinction keep USD price unavailable. See `web-wallet/docs/ixios-candidate-status.md` and `test/ixios-reference/ADMISSION.md`. TDC remains disabled without a usable provider; its post-handoff durable isolated host is implemented/tested but unregistered.

## Price behavior

Five verified CoinGecko identifiers added: ALGO, CKB, TDC, SOQ, XION. Existing strict symbol/confidence/freshness validation preserved. Earlier live read-only check accepted fresh ALGO/CKB/TDC; SOQ was stale and XION missing. Current display still requires a fresh valid quote; availability is not guaranteed. SPLD/ASE/QTC have no fabricated price mapping.

## Verification evidence

- Full suite before latest UI changes: 820 total / 722 passed / 98 skipped / 0 failed. These numbers are not the final UI aggregate.
- Latest ALGO controller/UI/storage focused run: 11/11 passed (mock providers only).
- Official algorand/falcon deterministic1024 native tests: 512 compressed cases + 32 conversions passed, GCC build.
- Separate native C signature oracle matches WASM byte-for-byte. Independent Python MessagePack matches signed payment fixture.
- Read-only mainnet algod **simulate**, synthetic unfunded account only: canonical native pqsig reached ledger overspend; bit-tampered signature explicitly rejected. This proves authentication interoperability, NOT funds or complete spendability. No `/transactions` submission request executed by tests.
- Latest UI aggregate completed: 831 total / 733 passed / 98 skipped / 0 failed. Web Wallet production build passed; Connect rerun OS-killed by resource pressure (earlier Connect build passed). Further changes require a final rerun.
- Live read-only indexer genesis and synthetic missing-ID search: HTTP 200, CORS *, expected genesis and indexed-through response.
- Extension build was killed by OS during transform, including bounded 768 MB JS heap attempt. This is resource failure, not permission denial.
- Isolated mocked-provider Chromium test could not start: sandbox `socket() Operation not permitted`; supported escalation failed before launch with bwrap read-only denied session-path error. No workaround, no real profile, no extension installation or credentials.

## Primary provenance

- Algorand transaction verification: https://github.com/algorand/go-algorand/blob/v5.0.0-stable/data/transactions/pqsig_test.go
- Algorand signer: https://github.com/algorand/go-algorand/blob/v5.0.0-stable/crypto/falconWrapper.go
- Falcon oracle source: https://github.com/algorand/falcon/tree/19f185792c39326bebc173b2a100c2c247423be3
- Indexer exact-id search: https://dev.algorand.co/reference/rest-api/indexer/operations/searchfortransactions/
- Simulator: https://dev.algorand.co/reference/rest-api/algod/operations/simulatetransaction/
- Source pins for other chains: existing `shared/crypto/sign/PQ_PORTS.md` and `web-wallet/README.md`, added fixture provenance/comments and `test/{xion,asentum}-reference/README.md`.

This checkpoint is deliberately partial. Extension/PQSwap send support for all eight is NOT complete.

## Later extension and history checkpoint

- Serial nonbrowser extension suite: 288/288 passed, zero skipped/failed. Eight browser-bearing files excluded due known browser-launch restriction; the unrestricted full suite attempt had 324 pass, 12 fail, 1 skip, including browser startup failures and resource-killed child processes. It is NOT a full browser pass.
- XION/SPLD live public schema fixtures preserved in `web-wallet/test/fixtures/pq-public-read-20261102/`; limited history filtered for native transfers, selected-network binding, cancellation and malformed/conflicting rows. Web/extension wiring focused set passed 18 cases before final additional guards.
- XION documented read-only testnet simulation with synthetic nonexistent payer returns HTTP 500 unknown account; this proves endpoint reachability only, not gas estimate or transaction acceptance.
- Extension packaging resource issue: nested Vite graph builds exceed this runner heap. Optional isolated-process driver reuses exact configs/plugins/targets and license union; validation in progress.

## 08:19 UTC checkpoint

- ALGO bounded source review confirms pending sender JSON is checksum address; ledger AuthAddr is the authority selector (no hidden Ed25519/PQ lock from pre-v42 funding). Mainnet candidate integrated, no funded broadcast or device QA.
- SOQ native controller and extension integrated; pre-submit lock race now covered by actual encrypted storage/lock/reopen test using a presealed authenticated cancellation capsule. Final independent integrated review and explicit exact-byte recovery still pending; send gates off.
- SPLD actual official Go v1.2.2 Transaction.Validate/DeriveAddress/VerifySignature and full hash match our signed envelope. Encrypted holder/payload validation and exact-byte recovery candidate exist. Shared capsule/UI integration and review remain; gates off.
- CKB actual deployed lock binary (verified type/data hash) executed via official checksum-verified ckb-standalone-debugger1.1.1 on synthetic tx: result0,26,462,819cycles. Signature/output tamper rejects107. Fee/cell reservation/controller/UI remain.
- QTC offline full witness/signing and network KDF tests pass; no native-node consensus acceptance/preflight/controller/UI.
- TDC native legacy Falcon signer3/3 exact pristine-source oracle tests. Exact node P2PKH transaction/sighash construction under implementation. Explorer403 not retried.
- XION limited history integrated; offline signer/protobuf/preflight ready. Config fee endpoint GET returned403 on both configuredmain/test public APIs; no retry. Simulation nonexistent-account response is not a gas estimate.
- ASE remains testnet-only; exact SDK signing/preflight ready, dynamic fee and independent-indexer identity not yet established. No invented mainnet or marketdata.
- Most recent full Web suite during ongoing edits:885total,785pass,98skip,2staleassertionfailures. Assertions updated for intentionally integrated histories/send dispatchers; final rerun required.
- Packaging remains blocked: isolated HTML builds succeed, standalone classicworker transforms1523modules then SIGKILLs; both minified and unminified runs fail. No complete extension archive is claimed. Optional isolated build driver is diagnostic, not proof of completed packaging.

## 08:36 UTC verification and packaging update

- Latest completed full Web aggregate:928 total,830 passed,98 skipped,0 failed; subsequent edits require another final aggregate. Latest actual Web SOQ callback/replay plus ALGO integration run:10/10 passed.
- Independent bounded review of Web SOQ, SPLD encrypted holder/recovery and ASE core/holder/recovery:20/20 passed, no concrete defect in reviewed scope. This is offline/mocked evidence, not live admission or complete UI review.
- SOQ candidate affected tests40/40 passed. CKB/QTC focused tests38/38 plus native/VM/regtest oracles passed. ASE adds real lock-during-replay test retaining prior uncertain reservation without a false cancellation proof.
- Extension packaging: existing system librsvg wrapper resolves icon generation without package installation. HTML phase succeeds. Classic worker still exceeds resources: isolated512MB heap/4MB young-generation attempt failed V8 heap exhaustion/SIGABRT; earlier larger heaps were OS-killed. No complete distributable or release exists.
- Browser startup/managed extension installation restrictions remain separate blockers; no workarounds attempted. Trusted internal Wallet integration does not add external PQSwap/dApp signing permissions.

## 08:39 UTC aggregate update

- Full serial Web aggregate completed:939 total,841 passed,98 skipped,0 failed (104.4s). Later concurrent extension/schema changes still require focused reruns.
- Independent reviewer rechecked CKB/QTC expiry fixes:20/20 tests including three clock-race regressions pass. Both now check expiry after durable persistence and before simulator disclosure; QTC also checks after signing/reverification before persistence.
- ASE integrated bounded review:5/5 holder/integration plus8/8 core/recovery passed. Trusted RPC now enforces the same capability policy as UI; testnet-only candidate enable and final guard rerun requested. Mainnet remains unsupported.

## 08:45 UTC integration update

- Nonbrowser extension aggregate:311/311 passed,0 skipped. Eight known browser-bearing test files were excluded explicitly; this does not claim browser/device QA.
- Fresh Web production build passed in6.34s. This is compilation evidence, not release packaging; subsequent gate/schema changes require rebuild.
- Independent Web review found same-hash attempt overwrite through ordinary catch/tracker writes. SOQ/SPLD now enforce attempt identity on ALL writes;6/6 regression tests pass and SOQ mainnet Web candidate is re-enabled. ALGO same-hash variant independently reproduced; WebALGO gate temporarily disabled until per-attempt authenticated ownership is implemented and reviewed. Extension holders use a separate architecture and are not implicated by this Web reproduction.
- SPLD extension mainnet candidate enabled after38/38 affected tests. ASE extension testnet candidate enabled with hard trusted RPC guard; unsupported networks and website provider methods rejected. XION trusted holder/RPC/UI exists but both network gates remain off.
- ASE Web transport read-only evidence: synthetic-Origin OPTIONS /tx returned204 with ACAO*, synthetic zero-address balance GET returned200 with ACAO*. Earlier8s OPTIONS timeout was inconclusive; bounded30s retry succeeded. No transaction POST was issued.

## 08:56 UTC packaging and current gates

- The extension resource blocker is RESOLVED: moving our generated1.7GB emsdk out of tmpfs into writable workspace overlay (same symlink path, verified compiler bytes) allowed the isolated minified production build to finish all graphs. This was resource remediation, not an access bypass.
- Static package verification3/3 passes: fixed baseline permissions/CSP, manifest identity/version, classic scripts, icons/pages/assets, byte-identical enabled-chain WASM and license union. No browser was launched or extension installed.
- Checkpoint ZIP: `/workspace/scratch/50eea9c5538b/nodus-connect-0.1.155-pq-candidate-20261102-0850.zip`,3,258,156 bytes,SHA256 `d583338640743137dcc36a8ac4075c6f148a1c70c12288c23ed9803b4774c2c7`. It predates later CKB/QTC integration; final rebuild remains required.
- ALGO Web authenticated per-attempt identity fixed same-hash competing-tab cancellation overwrite; mainnet candidate re-enabled after independent review. SOQ Web mainnet remains enabled. ASE Web testnet candidate enabled after bounded19/19 review; latest expanded27/27 focused tests pass. SPLD Web remains off due observed status-endpoint CORS restriction.
- XION deployed SDK source has conflicting validator-only documentation versus generic native-account verifier support; exact-source local in-memory CheckTx oracle is compiling. Simulation skips signature and global-fee validation and proves neither. Both XION send gates remain off.
- QTC official browser gateway is a distinct source-backed alternative to unavailable public node RPC, not a simulated broadcast: final submission only, canonical raw-prevout proof, strict body/input caps,409 never success, any exposure retains uncertainty. Variant31/31 focused tests pass; gate remains off pending review.
- IXIOS is a separate user research request, not a ninth send implementation. Verified activated protocol/status docs corrected without enabling or implementing sends.

## 09:34 UTC seven-network extension candidate

- Mainnet candidates: ALGO, SOQ, SPLD, CKB, QTC, Verona XION. ASE is testnet-only. TDC stays send-off for lack of usable official provider; its independently reviewed native consensus/script/policy and isolated controller are preserved.
- QTC default is the official structured-UTXO/final-gateway design under existing configured-provider trust. Independent source review proves epoch2 SIGHASH_DEFAULT commits actual input values/scripts/outpoints and all outputs; false claims cause invalid consensus signatures rather than excess-fee authorization. Native isolated node rejected false amount/script/output mutations. There is no denied /hex retry or alternate raw-data retrieval. Independent19/19+trusted-port1/1 review clean; enabled production gateway/holder/gate/port23/23 pass.
- XION official v32 release explicitly supports native MLDSA65 account keys. Exact deployed-source native oracle accepts wallet wire and >2^63 account number; incorrect signature/domain/account/sequence/lowfee reject. New sends have signed100-block timeout, height-pinned state, before-POST freshness checks. Provider-reported expiry closes only future-execution reservation after durable write; original outcome remains unknown, exact replay disabled, no automatic replacement. Actual trusted-port3/3 plus independent3/3 and affected90/90 pass. No fee default invented; globalfee403 not retried.
- CKB full-format recipients (hash types0/1/2/4, exact occupied-capacity floor) independently reviewed14/14 with deployed sender VM accepting standard61CKB output and rejecting altered capacity. Production expansion16/16 and broader50/50 pass; quantum inputs/change and no-type/empty-data restrictions stay. Long full-format addresses tested.
- Address book format checks now cover newly supported SPLD/ASE/CKB/QTC/XION without altering gates or the existing128-character storage bound; long CKB addresses can be pasted to send but cannot be saved.12/12 address-book tests pass.
- Most recent completed aggregates before final freeze: Web969 total/871passed/98skipped/0failed; nonbrowser extension354/354 passed. Fresh final aggregates and guarded production rebuild are in progress. Browser/device QA remains unrun; no deployment/push/real-money submission.

## Final frozen candidate validation — 09:45 UTC

- Full Web aggregate: **1,009 tests; 911 passed, 98 skipped, 0 failed**. The native Tidecoin oracle was enabled in this run. The skipped cases are existing optional native parity/build-dependent checks, not silently claimed passes.
- Serial nonbrowser extension aggregate: **361/361 passed**, zero skips/failures. Eight browser-bearing files were explicitly excluded; browser/device QA remains unrun.
- Production builds: Web **7.13s**, Connect **6.69s**, isolated minified extension **passed**. Static extension package verification **3/3 passed** after the final build.
- Runtime source fingerprint was identical before aggregates and after all builds. Fingerprint manifest SHA256: `bca6e1163c6a2166b33990843ac27608bb9abc6f79365c65d86cbe1d6d4c84d9`.
- Final prepared ZIP: `nodus-connect-0.1.155-pq-candidate-20261102-0943.zip`; **3,328,474 bytes**; SHA256 `f32f3871639519991fbeb84e9d982257d301f3f8d92483e63e3cff550af5b52e`.
- Seven trusted-extension candidates are enabled as scoped above; TDC remains off. No installed profile, remote repository, deployed site or live chain state was changed by this handoff.

## Final post-handoff IXIOS candidate validation (2026-11-02 10:19 UTC)

- Runtime source frozen across final tests and builds; fingerprint manifest SHA256 `8251442211c7dd295e17c37e2c4854b95f1c9945cfa2dbd1caccb1776eac1f3d`.
- Web: 1,030 total, 932 passed, 98 skipped, zero failed (native Tidecoin oracle enabled).
- Explicit nonbrowser extension list:383/383 passed; all8 known browser-bearing files excluded and checked before execution. Static package tests separately3/3 passed.
- Web production8.65s, Connect8.45s, isolated minified extension build passed. No install/deploy.
- Native IXIOS admission10/10 offline, including external browser-WASM hedged raw decoded without re-signing, native sender recovery and ApplyTransaction state deltas. Native gas1000, source-floor fixture fee93 IXIOS. No live acceptance claim.
- An earlier broad test glob accidentally included browser-bearing ixios.test.js; its synthetic browser failed `socket() Operation not permitted`. Failure preserved in handoff logs, no subsequent browser retry. Final counts are not an unrestricted extension/browser pass.
- Mainnet trusted code candidate IXIOS enabled; runtime identity/fresh fee checks fail closed. BatchRPC403 remains unresolved, exact later single-query chronology retained; all live probes stopped. Official Coinstore USDT price identity does not provide a verified USD quote.
- TDC remains off; isolated encrypted holder/recovery is implemented and reviewed, but production transport remains unavailable.
