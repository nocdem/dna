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
#                        own verify and signing preimage; outbox blob decrypt
#                        + authorship; alg selection; salt packet v1;
#                        contact-list blob read as the app's fetch does; ACK
#                        value; key derivation (pure, no network)
#   test_nc_fault_matrix R0 against a fake node over real tier-2: timeout,
#                        empty, bad signature, wrong owner, undecodable — no
#                        PUT on UNREADABLE; Q1 create gate; KEY_OWNED = taken;
#                        the same gates for the contact list and the salt
#   test_nc_history      NC-4a at-rest history crypto: NIST HMAC-SHA3-256
#                        KAT, root = app SQLCipher derivation, HKDF key,
#                        AES-GCM records, AAD framing, invocation budget
#   test_nc_group        G1 groups codec: every preimage / digest / address /
#                        KEK / wrapped key / record / bucket of the oracle's
#                        groups_kat.json byte-compared, signatures verified,
#                        KEM round trip, every reject case refused
#   test_nc_rules        P1 rules: every shared vector (generated from the
#                        JS of src/connect/ui/actions.js) byte-equal through
#                        nc_rule_call; malformed JSON inputs; ASan + UBSan
cmake_minimum_required(VERSION 3.16)
project(nodus_connect_tests C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

get_filename_component(ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../.." ABSOLUTE)
set(CONNECT_DIR "${ROOT}/web-wallet/connect")

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_path(SQLITE3_INCLUDE sqlite3.h REQUIRED)

# json-c: the SAME version and source as the wasm module (design P1 rev 2
# §3, red-team R6 — native ctest used the host's json-c 0.16 while the wasm
# links 0.17). scripts/build-jsonc-wasm.sh downloads tag json-c-0.17-20230812
# once and pins it by SHA-256; that verified tarball is built here, natively
# and statically, with the wasm build's options (BUILD_SHARED_LIBS=OFF,
# BUILD_STATIC_LIBS=ON, BUILD_APPS=OFF, BUILD_TESTING=OFF, Release; json-c's
# default -Werror kept). CMake extracts the local file; nothing is
# downloaded. Without the tarball the host json-c (pkg-config) is used and
# the configure step says so — then native and wasm json-c differ.
set(JSONC_TARBALL "$ENV{HOME}/wasm-deps/src/json-c-0.17-20230812.tar.gz"
    CACHE FILEPATH "json-c 0.17 tarball fetched by scripts/build-jsonc-wasm.sh")
set(JSONC_SHA256 "024d302a3aadcbf9f78735320a6d5aedf8b77876c8ac8bbb95081ca55054c7eb")
if(EXISTS "${JSONC_TARBALL}")
  include(ExternalProject)
  ExternalProject_Add(jsonc017
    URL "${JSONC_TARBALL}"
    URL_HASH SHA256=${JSONC_SHA256}
    DOWNLOAD_EXTRACT_TIMESTAMP ON
    CMAKE_ARGS
      -DCMAKE_BUILD_TYPE=Release
      -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
      -DCMAKE_INSTALL_LIBDIR=lib
      -DCMAKE_POSITION_INDEPENDENT_CODE=ON
      -DBUILD_SHARED_LIBS=OFF
      -DBUILD_STATIC_LIBS=ON
      -DBUILD_APPS=OFF
      -DBUILD_TESTING=OFF
    BUILD_BYPRODUCTS <INSTALL_DIR>/lib/libjson-c.a)
  ExternalProject_Get_Property(jsonc017 INSTALL_DIR)
  file(MAKE_DIRECTORY "${INSTALL_DIR}/include")
  add_library(jsonc_static STATIC IMPORTED)
  set_target_properties(jsonc_static PROPERTIES
    IMPORTED_LOCATION "${INSTALL_DIR}/lib/libjson-c.a"
    INTERFACE_INCLUDE_DIRECTORIES "${INSTALL_DIR}/include")
  add_dependencies(jsonc_static jsonc017)
  set(NC_JSONC_INCLUDE "${INSTALL_DIR}/include")
  set(NC_JSONC_LIBS jsonc_static)
  set(NC_JSONC_LIBDIRS "")
  message(STATUS "json-c: 0.17 from ${JSONC_TARBALL} (same tag as the wasm)")
else()
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(JSONC REQUIRED json-c)
  set(NC_JSONC_INCLUDE ${JSONC_INCLUDE_DIRS})
  set(NC_JSONC_LIBS ${JSONC_LIBRARIES})
  set(NC_JSONC_LIBDIRS ${JSONC_LIBRARY_DIRS})
  message(WARNING "json-c: ${JSONC_TARBALL} not found (scripts/build-jsonc-wasm.sh fetches it); "
                  "using the host json-c ${JSONC_VERSION} — NOT the wasm's 0.17")
endif()

set(NC_SOURCES
  ${CONNECT_DIR}/nc_keys.c
  ${CONNECT_DIR}/nc_read.c
  ${CONNECT_DIR}/nc_servers.c
  ${CONNECT_DIR}/nc_profile.c
  ${CONNECT_DIR}/nc_requests.c
  ${CONNECT_DIR}/nc_salt.c
  ${CONNECT_DIR}/nc_outbox.c
  ${CONNECT_DIR}/nc_history.c
  ${CONNECT_DIR}/nc_contactlist.c
  ${CONNECT_DIR}/nc_group.c
  # P1 rules (design 2026-10-12-connect-core-p1-rules-design.md rev 2)
  ${CONNECT_DIR}/nc_jsjson.c
  ${CONNECT_DIR}/nc_payload.c
  ${CONNECT_DIR}/nc_rules_json.c
  ${ROOT}/messenger/codec/contact_request_codec.c
  ${ROOT}/messenger/codec/contactlist_codec.c
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
  # nodus_client.c includes dnac/dnac.h (HF-4 name check); the wasm build
  # has -I$root/dnac/include (scripts/build-nodus-send-wasm.sh)
  ${ROOT}/dnac/include
  ${ROOT}/messenger ${ROOT}/messenger/include
  ${NC_JSONC_INCLUDE} ${OPENSSL_INCLUDE_DIR} ${SQLITE3_INCLUDE})
target_compile_options(nc_core PRIVATE -Wall -Wextra -Wno-unused-parameter -Werror)
set_source_files_properties(${ROOT}/shared/crypto/utils/qgp_fingerprint.c
  PROPERTIES COMPILE_OPTIONS "-Wno-unknown-warning-option;-Wno-unterminated-string-initialization")
target_link_libraries(nc_core PUBLIC OpenSSL::Crypto ${NC_JSONC_LIBS}
  Threads::Threads m)
target_link_directories(nc_core PUBLIC ${NC_JSONC_LIBDIRS})

enable_testing()
foreach(t test_nc_classify test_nc_wire test_nc_fault_matrix)
  add_executable(${t} ${t}.c)
  target_link_libraries(${t} nc_core)
  target_compile_options(${t} PRIVATE -Wall -Wextra -Wno-unused-parameter -Werror)
  add_test(NAME ${t} COMMAND ${t})
endforeach()

# NC-4a: the app's SQLCipher key derivation is compiled in to compare the
# history root against it; no SQLCipher library is linked — the unit's
# sqlite-calling function is unreferenced and dropped by --gc-sections.
add_executable(test_nc_history test_nc_history.c
  ${ROOT}/messenger/database/db_encryption.c)
target_link_libraries(test_nc_history nc_core)
target_compile_options(test_nc_history PRIVATE -Wall -Wextra -Wno-unused-parameter -Werror)
add_test(NAME test_nc_history COMMAND test_nc_history)

# G1: the groups codec against the independent oracle's vectors
# (web-wallet/test/fixtures/groups_kat.json, read at run time).
add_executable(test_nc_group test_nc_group.c)
target_link_libraries(test_nc_group nc_core)
target_compile_options(test_nc_group PRIVATE -Wall -Wextra -Wno-unused-parameter -Werror)
target_compile_definitions(test_nc_group PRIVATE
  GROUPS_KAT="${ROOT}/web-wallet/test/fixtures/groups_kat.json")
add_test(NAME test_nc_group COMMAND test_nc_group)

# P1: the shared rule vectors (web-wallet/test/vectors/connect-rules/*.json,
# read at run time) through nc_rule_call, plus malformed inputs. The rule
# sources are compiled INTO the test with AddressSanitizer + UBSan (any
# finding aborts: -fno-sanitize-recover=all), so the code under test is
# instrumented; their uninstrumented copies in nc_core are not pulled in
# (every symbol is already defined by the test's own objects).
set(NC_RULES_SOURCES
  ${CONNECT_DIR}/nc_jsjson.c
  ${CONNECT_DIR}/nc_payload.c
  ${CONNECT_DIR}/nc_rules_json.c)
add_executable(test_nc_rules test_nc_rules.c ${NC_RULES_SOURCES})
target_link_libraries(test_nc_rules nc_core)
target_compile_options(test_nc_rules PRIVATE -Wall -Wextra -Wno-unused-parameter -Werror
  -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
target_link_options(test_nc_rules PRIVATE -fsanitize=address,undefined)
target_compile_definitions(test_nc_rules PRIVATE
  VECTORS_DIR="${ROOT}/web-wallet/test/vectors/connect-rules")
add_test(NAME test_nc_rules COMMAND test_nc_rules)

# NC-3a: live READ-ONLY probe against a real node (not a ctest: it needs a
# words file and a live server; see its file header).
add_executable(nc_live_read ${CONNECT_DIR}/tools/nc_live_read.c)
target_link_libraries(nc_live_read nc_core)
target_compile_options(nc_live_read PRIVATE -Wall -Wextra -Wno-unused-parameter -Werror)
