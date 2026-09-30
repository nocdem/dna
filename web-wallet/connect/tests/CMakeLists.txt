# Nodus Connect thin core (package NC-2) — native unit tests.
#
# Builds the SAME compile set as scripts/build-connect-wasm.sh, natively:
# the library (connect/nc_*.c except the browser entry nc_wasm.c), the
# message codecs from messenger/codec/, messenger/dna_api.c,
# messenger/dht/client/dna_profile.c, the nodus client sources and the
# shared crypto. The one difference is the platform file: natively
# shared/crypto/utils/qgp_platform_linux.c provides qgp_platform_random /
# qgp_secure_memzero / qgp_platform_home_dir (the wasm entry defines its
# own).
#
#   cd web-wallet/connect/tests && mkdir -p build && cd build
#   cmake .. && make && ctest --output-on-failure
#
# Tests (what each proves is in its file header):
#   test_nc_classify     R0 classifier matrix + server list + salt choice (pure)
#   test_nc_wire         request / acceptance / cancel bytes vs the codec's
#                        own verify; outbox blob decrypt + authorship; alg
#                        selection; key derivation (pure, no network)
#   test_nc_fault_matrix R0 against a fake node over real tier-2: timeout,
#                        empty, bad signature, wrong owner, undecodable — no
#                        PUT on UNREADABLE; Q1 create gate; KEY_OWNED = taken
cmake_minimum_required(VERSION 3.16)
project(nodus_connect_tests C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

get_filename_component(ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../.." ABSOLUTE)
set(CONNECT_DIR "${ROOT}/web-wallet/connect")

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(JSONC REQUIRED json-c)
find_path(SQLITE3_INCLUDE sqlite3.h REQUIRED)

set(NC_SOURCES
  ${CONNECT_DIR}/nc_keys.c
  ${CONNECT_DIR}/nc_read.c
  ${CONNECT_DIR}/nc_servers.c
  ${CONNECT_DIR}/nc_profile.c
  ${CONNECT_DIR}/nc_requests.c
  ${CONNECT_DIR}/nc_salt.c
  ${CONNECT_DIR}/nc_outbox.c
  ${ROOT}/messenger/codec/contact_request_codec.c
  ${ROOT}/messenger/codec/dm_outbox_codec.c
  ${ROOT}/messenger/codec/offline_queue_codec.c
  ${ROOT}/messenger/codec/salt_agreement_codec.c
  ${ROOT}/messenger/codec/seal_multi_codec.c
  ${ROOT}/messenger/codec/gek_wrap_codec.c
  ${ROOT}/messenger/dna_api.c
  ${ROOT}/messenger/dht/client/dna_profile.c
  ${ROOT}/nodus/src/client/nodus_client.c
  ${ROOT}/nodus/src/transport/nodus_tcp.c
  # native nodus_tcp.c also carries the server's WebSocket entry (the
  # __EMSCRIPTEN__ branch does not); its codec lives here
  ${ROOT}/nodus/src/transport/nodus_ws.c
  ${ROOT}/nodus/src/protocol/nodus_tier2.c
  ${ROOT}/nodus/src/protocol/nodus_cbor.c
  ${ROOT}/nodus/src/protocol/nodus_wire.c
  ${ROOT}/nodus/src/core/nodus_value.c
  ${ROOT}/nodus/src/crypto/nodus_sign.c
  ${ROOT}/nodus/src/crypto/nodus_identity.c
  ${ROOT}/nodus/src/crypto/nodus_channel_crypto.c
  ${ROOT}/nodus/src/nodus_log_shim.c
  ${ROOT}/shared/crypto/key/bip39/bip39.c
  ${ROOT}/shared/crypto/key/bip39/bip39_pbkdf2.c
  ${ROOT}/shared/crypto/key/bip39/seed_derivation.c
  ${ROOT}/shared/crypto/hash/qgp_sha3.c
  ${ROOT}/shared/crypto/hash/hkdf_sha3.c
  ${ROOT}/shared/crypto/utils/qgp_random.c
  ${ROOT}/shared/crypto/utils/qgp_fingerprint.c
  ${ROOT}/shared/crypto/utils/qgp_platform_linux.c
  ${ROOT}/shared/crypto/sign/qgp_signature.c
  ${ROOT}/shared/crypto/sign/qgp_dilithium.c
  ${ROOT}/shared/crypto/sign/dsa/sign.c
  ${ROOT}/shared/crypto/sign/dsa/packing.c
  ${ROOT}/shared/crypto/sign/dsa/polyvec.c
  ${ROOT}/shared/crypto/sign/dsa/poly.c
  ${ROOT}/shared/crypto/sign/dsa/ntt.c
  ${ROOT}/shared/crypto/sign/dsa/rounding.c
  ${ROOT}/shared/crypto/sign/dsa/reduce.c
  ${ROOT}/shared/crypto/sign/dsa/fips202.c
  ${ROOT}/shared/crypto/sign/dsa/symmetric-shake.c
  ${ROOT}/shared/crypto/enc/qgp_aes.c
  ${ROOT}/shared/crypto/enc/aes_keywrap.c
  ${ROOT}/shared/crypto/enc/qgp_kyber.c
  ${ROOT}/shared/crypto/enc/kyber_r3_legacy.c
  ${ROOT}/shared/crypto/enc/qgp_mlkem.c
  ${ROOT}/shared/crypto/enc/kem/cbd.c
  ${ROOT}/shared/crypto/enc/kem/fips202.c
  ${ROOT}/shared/crypto/enc/kem/indcpa.c
  ${ROOT}/shared/crypto/enc/kem/kem.c
  ${ROOT}/shared/crypto/enc/kem/ntt.c
  ${ROOT}/shared/crypto/enc/kem/poly.c
  ${ROOT}/shared/crypto/enc/kem/polyvec.c
  ${ROOT}/shared/crypto/enc/kem/reduce.c
  ${ROOT}/shared/crypto/enc/kem/symmetric-shake.c
  ${ROOT}/shared/crypto/enc/kem/verify.c
)

add_library(nc_core STATIC ${NC_SOURCES})
# wasm-ld drops unreferenced functions by default (--gc-sections); dna_api.c
# carries key-file helpers (qgp_key_load, ...) nothing here calls. The same
# section GC is applied natively so both builds link the same live code.
target_compile_options(nc_core PUBLIC -ffunction-sections -fdata-sections)
target_link_options(nc_core PUBLIC -Wl,--gc-sections)
target_include_directories(nc_core PUBLIC
  ${CONNECT_DIR}
  ${ROOT}/nodus/include ${ROOT}/nodus/src
  ${ROOT}/shared
  ${ROOT}/messenger ${ROOT}/messenger/include
  ${OPENSSL_INCLUDE_DIR} ${JSONC_INCLUDE_DIRS} ${SQLITE3_INCLUDE})
target_compile_options(nc_core PRIVATE -Wall -Wextra -Wno-unused-parameter -Werror)
set_source_files_properties(${ROOT}/shared/crypto/utils/qgp_fingerprint.c
  PROPERTIES COMPILE_OPTIONS "-Wno-unknown-warning-option;-Wno-unterminated-string-initialization")
target_link_libraries(nc_core PUBLIC OpenSSL::Crypto ${JSONC_LIBRARIES}
  Threads::Threads m)
target_link_directories(nc_core PUBLIC ${JSONC_LIBRARY_DIRS})

enable_testing()
foreach(t test_nc_classify test_nc_wire test_nc_fault_matrix)
  add_executable(${t} ${t}.c)
  target_link_libraries(${t} nc_core)
  target_compile_options(${t} PRIVATE -Wall -Wextra -Wno-unused-parameter -Werror)
  add_test(NAME ${t} COMMAND ${t})
endforeach()
