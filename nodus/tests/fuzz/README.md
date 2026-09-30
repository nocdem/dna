# Nodus fuzz targets

libFuzzer harnesses for the decoders a **client** runs on bytes a node sends:
the tier-2 reply decode, the CBOR decoder under it, and the signed DHT value
decode. Added by web Connect package NC-5 (`docs/plans/2026-09-24-web-connect-design.md`
rev 5, §5 A2 / §8) because the browser build of the tier-2 client runs these
decoders with a 32-bit `size_t`. Layout follows `messenger/tests/fuzz/` and
`messenger/docs/FUZZING.md`.

## Targets

| Target | Entry points | Covers |
|---|---|---|
| `fuzz_t2_decode` | `nodus_frame_decode` + `nodus_frame_validate` (`src/protocol/nodus_wire.c:41`), `nodus_t2_decode` (`src/protocol/nodus_tier2.c:2898`), `nodus_value_verify` on every decoded value, `nodus_t2_msg_free` | A complete TCP frame is unwrapped first; anything else is decoded as a tier-2 payload. After the handshake that payload is the plaintext a node produced, so a malicious or buggy node controls all of it. |
| `fuzz_cbor` | `cbor_decode_skip_signed`, `cbor_decode_peek` / `_next` / `_int`, `cbor_map_find` (`src/protocol/nodus_cbor.h`) | Skip-walk, flat walk that reads every byte of every returned bstr/tstr slice (an out-of-range slice fails here, under ASan), and a map key lookup. |
| `fuzz_value` | `nodus_value_deserialize` (`src/core/nodus_value.c:305`), `nodus_value_verify`, `nodus_value_serialize`, `nodus_value_free` | The signed value the web core's read primitive checks before acting on it (design §1.4 R0, §5 G10); decoded values are re-serialised. |

`fuzz_seed_gen` writes the seed corpora with the real encoders
(`nodus_value_create/_sign/_serialize`, `nodus_t2_result` / `_result_multi` /
`_result_empty` / `_error` / `_pong` / `_put_ok` / `_value_changed` /
`_challenge` / `_auth_ok`, `nodus_frame_encode`). The signing key is fixed
(`nodus_identity_from_seed`); signatures are randomized
(`shared/crypto/sign/dsa/config.h:6`), so a re-run writes different — equally
valid — bytes.

## Build (native, libFuzzer + ASan, clang)

```bash
cd nodus
mkdir -p build-fuzz && cd build-fuzz
CC=clang cmake -DNODUS_FUZZ=ON ..
make -j$(nproc) fuzz_t2_decode fuzz_cbor fuzz_value fuzz_seed_gen
./fuzz_seed_gen ../tests/fuzz/corpus        # writes value/ t2_decode/ cbor/
```

`NODUS_FUZZ` (default OFF, `nodus/CMakeLists.txt`, last block) compiles the
whole `nodus` library with `-fsanitize=fuzzer-no-link,address`, so it needs its
own build directory. Nothing is registered with ctest.

## Run

```bash
./fuzz_t2_decode ../tests/fuzz/corpus/t2_decode/ -max_total_time=600
./fuzz_cbor      ../tests/fuzz/corpus/cbor/      -max_total_time=600
./fuzz_value     ../tests/fuzz/corpus/value/     -max_total_time=600
./fuzz_t2_decode crash-<hash>                    # reproduce a finding
```

## Build and run for wasm32 (32-bit `size_t`)

```bash
bash nodus/tests/fuzz/build_wasm32.sh              # -> nodus/build-fuzz-wasm32/
node nodus/build-fuzz-wasm32/fuzz_t2_decode.js nodus/tests/fuzz/corpus/t2_decode/
node nodus/build-fuzz-wasm32/fuzz_t2_decode.js -mutate=20000 -seed=1 nodus/tests/fuzz/corpus/t2_decode/
node nodus/build-fuzz-wasm32/fuzz_t2_decode.js crash-<hash>   # native finding, replayed at 32 bits
```

Emscripten 6.0.10 (pinned, the version the OpenSSL wasm archive
`~/wasm-deps/openssl-3.0.15-wasm` is built with), `-fsanitize=address`.
Emscripten has no libFuzzer, so each harness is linked with `fuzz_driver.c`:
replay of every file (directories sorted by name) plus an optional
deterministic mutation pass (`-mutate=N -seed=S`, xorshift64; bit flips, byte
sets, 32-bit edge lengths such as `0xFFFFFFFF` / `0x80000000` in both byte
orders, truncation). `fuzz_wasm_platform.c` supplies a deterministic
`qgp_platform_random` (test only — nothing here is secret) and
`qgp_secure_memzero`; `fuzz_wasm_log.c` is the QGP log back end.

A plain `-m32` build is not provided: this machine has no 32-bit libc
development files (`libc6-dev-i386`) or i386 OpenSSL. With them installed,
`fuzz_driver.c` + the same source list as `build_wasm32.sh` is the build.

## What these targets cannot find

- **Anything past the decoder.** `nodus_client.c`'s handling of a decoded
  reply (request correlation, the three-outcome read of design §1.4 R0, auth
  and key exchange state) is not driven — it is static and bound to a live
  socket. The web core's R0 will need its own harness once it exists (NC-2).
- **The channel layer.** Frames are fuzzed after decryption; the AES-GCM
  record layer (`nodus_channel_crypto.c`) and the ML-KEM handshake are not.
- **Signature forgery.** `nodus_value_verify` runs on every decoded value, but
  a random signature does not verify, so code behind a successful verify gets
  coverage only from the seed values.
- **Uninstrumented code.** `dsa` / `kem` (crypto) and OpenSSL are linked
  without coverage instrumentation; libFuzzer steers by the nodus library only.
- **wasm32 is not coverage guided.** The wasm32 programs replay and mutate
  deterministically; they find what the inputs reach, nothing more. Their job
  is to re-run the native corpus and crash files with 32-bit arithmetic.
