#!/usr/bin/env bash
# The NODUS send module: C -> WebAssembly (web wallet package (c3); design
# docs/plans/2026-09-25-web-wallet-nodus-send-design.md rev 2 §0a.3 "(c3)",
# §1.3). One module = the nodus tier-2 client (package (c1), browser
# branches), the shared SPEND builder nodus-cli uses (package (c2),
# nodus/src/client/nodus_v2_spend.c + the generated
# nodus/include/nodus/nodus_ruleset_pins.h) and crypto/nodus-send-wasm.c,
# the entry points src/nodus/send-module.js calls. Since NC-4b the SAME
# module also carries the Nodus Connect thin core (web-wallet/connect/, JSON
# exports connect/nc_wasm.c) on the one session of this module — the
# wallet's one module of design docs/plans/2026-09-24-web-connect-design.md
# rev 5 §1.1 (two sessions of one identity evict each other on a node,
# nodus_auth.c:95-116). src/connect/core.js drives it through the wallet's
# queue (src/nodus/client.js).
#
# Usage:
#   build-nodus-send-wasm.sh            the SHIPPED module (-DNODUS_SEND_RELEASE)
#                                       -> src/nodus/send.js + src/nodus/send.wasm
#   build-nodus-send-wasm.sh parity     two node-environment builds for the
#                                       parity test (test/nodus-send-wasm.test.js),
#                                       -> $NODUS_SEND_PARITY_OUT
#                                          (default /tmp/nodus-send-parity):
#                                       send-node.mjs       release C flags
#                                       send-test-node.mjs  -DNODUS_SEND_TEST_FIXED_RANDOM
#                                       Never written under src/.
# The TEST define cannot reach the shipped module: this script passes it only
# in `parity` mode and only into that directory, and nodus-send-wasm.c
# refuses to compile it together with NODUS_SEND_RELEASE (#error).
#
# Toolchain: Emscripten 6.0.10 exactly (checked below). It is the version
# the linked OpenSSL archive is built with (scripts/build-openssl-wasm.sh
# EMCC_REQUIRED_VERSION) — one toolchain for every object in the link. The
# Asyncify spike of design §1.3 ran on 4.0.16; its result is not re-measured
# on 6.0.10 by this script (building only, nothing is run).
#   EMSDK (default ~/emsdk) or EMCC_BIN (default $EMSDK/upstream/emscripten/emcc)
#   OPENSSL_WASM_PREFIX (default ~/wasm-deps/openssl-3.0.15-wasm; built by
#     scripts/build-openssl-wasm.sh): include/ and lib/libcrypto.a
#   SQLITE3_H (default /usr/include/sqlite3.h): declarations-only header
#     nodus/include/nodus/nodus.h pulls in through the media/channel store
#     headers (the same trick as scripts/check-nodus-client-wasm.sh); no
#     sqlite code is compiled or linked.
#
# Link settings, and why:
#   ASYNCIFY=1            one thread; every client wait yields through
#                         emscripten_sleep (nodus_client.c client_yield)
#                         — decision 2026-09-25-web-wallet-nodus-send-transport.md
#                         "Çalışma modeli"
#   ASYNCIFY_STACK_SIZE   see ASYNCIFY_STACK below
#   STACK_SIZE 1 MiB      the C stack: ML-DSA-87 signing peaks near 121 KB
#                         (scripts/build-mldsa87-sign-wasm.sh), keypair
#                         derivation ~97 KB, plus the client/builder frames
#   WEBSOCKET_URL wss://  SOCKFS connect() opens wss://<ip>:<port>/ unless the
#                         page passes Module.websocket.url (send-module.js
#                         does, from its network settings)
#   ENVIRONMENT web       the shipped glue has no node branch
#   MODULARIZE/EXPORT_ES6 an ES module factory; Vite resolves send.wasm next
#                         to it
set -euo pipefail
cd "$(dirname "$0")/.."            # web-wallet/
root=..

EMCC_REQUIRED_VERSION="6.0.10"
EMSDK="${EMSDK:-$HOME/emsdk}"
EMCC_BIN="${EMCC_BIN:-$EMSDK/upstream/emscripten/emcc}"
OPENSSL_WASM_PREFIX="${OPENSSL_WASM_PREFIX:-$HOME/wasm-deps/openssl-3.0.15-wasm}"
# Messages (NC-4b): the Anchor record codec and the nc_* results are json-c
# (scripts/build-jsonc-wasm.sh). The Anchor signature is over json-c's
# re-serialisation: the json-c version the frozen app was built with is NOT
# established (printed below for the record; README "Nodus Connect").
JSONC_WASM_PREFIX="${JSONC_WASM_PREFIX:-$HOME/wasm-deps/json-c-0.17-wasm}"
SQLITE3_H="${SQLITE3_H:-/usr/include/sqlite3.h}"
mode="${1:-release}"

# Asyncify's unwind buffer (ASYNCIFY_STACK_SIZE). At an emscripten_sleep
# Asyncify saves, for every frame on the stack between the export and the
# sleep, that frame's locals plus a 4-byte call index. STATIC bound for this
# module, from the disassembly of the same link with --profiling-funcs
# (emsdk 6.0.10, -O2, 2026-09-30; not measured at run time — nothing is
# run): only 12 functions reach emscripten_sleep through direct calls, no
# indirect-call (table) target is among them, and the heaviest chain is
#   nsw_scan(244 B) -> nsw_session_ok(16) -> nsw_check_chain(44)
#     -> wait_response(76) -> emscripten_sleep  = 380 bytes
# counting EVERY param and local of each frame (an upper bound of what is
# saved). 16384 is ~43x that, so inlining changes in later edits stay far
# inside it. The genesis-claim exports of 0.1.26 (nsw_claim_status /
# _build / _submit) add chains of the same shape (export -> nsw_session_ok
# / nsw_check_chain / nodus_client_dnac_* -> wait_response); their frames
# were NOT re-measured from a --profiling-funcs disassembly for this
# release. They keep every large object on the heap or in static storage
# (dna_claim_t, the claim bytes, the supply buckets are small), so the
# bound above is expected to hold — expected, not measured.
# The staking exports of 0.1.29 (nsw_validators, nsw_delegations,
# nsw_stake_build) have the same shape: every network wait runs in the
# export's own frame with small scalar locals (the page / result structs are
# a count and a heap pointer), the validator and delegation caches are
# static, and the builder's large structs are heap-allocated in
# nsw_stake_core, which runs only after the last wait. Also expected, not
# re-measured.
# The Messages exports of NC-4b (nc_*) have the shape export -> nc_* library
# -> nodus_client_get_strict / get_all / put_ex -> wait_response ->
# emscripten_sleep; their records, identities and value lists are on the
# heap or in static storage. Their frames were NOT measured from a
# --profiling-funcs disassembly: expected to hold, not measured.
# The HF-4 exports (nsw_ruleset_info, nsw_name_lookup, nsw_name_of,
# nsw_profile_address) and the generation choice added to nsw_build_and_sign
# / nsw_stake_build have the same shape: the answer structs
# (nodus_dnac_ruleset_info_t ~230 B, nodus_dnac_name_result_t ~190 B, the
# profile read's nc_read_t) have their address taken, so they live on the
# C stack, not in the unwind buffer; the profile itself is heap. Expected to
# hold, not measured.
# The chain-name registration exports (nsw_name_prices, nsw_name_build)
# have the same shape: every wait (dnac_ruleset_info, dnac_name_lookup,
# dnac_name_of, dnac_fee_info's name prices and gas price) runs in the
# export's own frame; the answer structs have their address taken (C
# stack, not the unwind buffer), and the builder's large structs are
# heap-allocated in nsw_name_core, which runs only after the last wait.
# Expected to hold, not measured.
# The vault exports (nsw_msig_member_add, _balance, _scan, _build, _review,
# _submit) have the same shape: every wait runs in the export's own frame;
# the profile read's nc_read_t and the answer structs have their address
# taken (C stack), the vault state is static, and the builder / review /
# combine structs are heap-allocated after the last wait. Expected to hold,
# not measured.
# The smart-contract exports (nsw_evm_call / _create / _deposit /
# _withdraw / _redeem) have the same shape as nsw_build_and_sign: every
# wait (chain id, dnac_ruleset_info, dnac_fee_info) runs in nsw_evm_net's
# own frame with scalar locals and address-taken answer structs (C stack);
# the meter policy, the builder's buffers and structs are heap-allocated
# in nsw_evm_core, which runs only after the last wait. Expected to hold,
# not measured.
# There is no ASYNCIFY_ONLY / ASYNCIFY_ADD list: with ASYNCIFY=1 Binaryen
# instruments every function that can reach emscripten_sleep (directly or,
# with the default ASYNCIFY_IGNORE_INDIRECT=0, through an indirect call),
# so a new export that waits is covered by the link itself; what the JS
# side must do is call it with ccall { async: true } (send-module.js,
# src/connect/core.js).
# The default ASYNCIFY_IGNORE_INDIRECT=0 is kept: Asyncify still
# instruments every function with an indirect call (OpenSSL's provider
# tables, the builder's rand callback), which costs size, not correctness.
ASYNCIFY_STACK=16384

case "$mode" in
  release|parity) ;;
  *) echo "build-nodus-send-wasm: unknown mode '$mode' (release | parity)" >&2; exit 2 ;;
esac
if [ ! -x "$EMCC_BIN" ]; then
  echo "build-nodus-send-wasm: $EMCC_BIN not found (set EMSDK or EMCC_BIN)" >&2
  exit 2
fi
emcc_line="$("$EMCC_BIN" --version | head -1)"
echo "$emcc_line"
case "$emcc_line" in
  *" ${EMCC_REQUIRED_VERSION} "*) ;;
  *) echo "build-nodus-send-wasm: emcc ${EMCC_REQUIRED_VERSION} required (pinned toolchain), found: $emcc_line" >&2
     exit 2 ;;
esac
if [ ! -f "$OPENSSL_WASM_PREFIX/lib/libcrypto.a" ] || [ ! -f "$OPENSSL_WASM_PREFIX/include/openssl/evp.h" ]; then
  echo "build-nodus-send-wasm: OpenSSL wasm build missing under $OPENSSL_WASM_PREFIX (run scripts/build-openssl-wasm.sh)" >&2
  exit 2
fi
if [ ! -f "$JSONC_WASM_PREFIX/lib/libjson-c.a" ] || [ ! -f "$JSONC_WASM_PREFIX/include/json-c/json.h" ]; then
  echo "build-nodus-send-wasm: json-c wasm build missing under $JSONC_WASM_PREFIX (run scripts/build-jsonc-wasm.sh)" >&2
  exit 2
fi
if [ ! -f "$SQLITE3_H" ]; then
  echo "build-nodus-send-wasm: $SQLITE3_H not found (set SQLITE3_H)" >&2
  exit 2
fi
echo "json-c (wasm): $(sed -n 's/^Version: //p' "$JSONC_WASM_PREFIX/lib/pkgconfig/json-c.pc" 2>/dev/null || echo unknown)"
echo "json-c (host, informational): $(pkg-config --modversion json-c 2>/dev/null || echo unknown)"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/inc"
cp "$SQLITE3_H" "$work/inc/sqlite3.h"

sources=(
  crypto/nodus-send-wasm.c
  # Messages (NC-4b): the Nodus Connect thin core and its JSON exports, on
  # this module's session (nodus-send-wasm.c "Messages host"). Same set as
  # connect/tests/CMakeLists.txt NC_SOURCES, minus the platform file.
  connect/nc_wasm.c
  connect/nc_keys.c
  connect/nc_read.c
  connect/nc_servers.c
  connect/nc_profile.c
  connect/nc_requests.c
  connect/nc_salt.c
  connect/nc_outbox.c
  connect/nc_history.c
  connect/nc_contactlist.c
  # groups codec (G1 nc_group.h; exports nc_group_* in nc_wasm.c, G2)
  connect/nc_group.c
  # message codecs, verbatim (NC-1, NC-1b)
  $root/messenger/codec/contact_request_codec.c
  $root/messenger/codec/contactlist_codec.c
  $root/messenger/codec/dm_outbox_codec.c
  $root/messenger/codec/offline_queue_codec.c
  $root/messenger/codec/salt_agreement_codec.c
  $root/messenger/codec/seal_multi_codec.c
  $root/messenger/codec/gek_wrap_codec.c
  # Seal decode / authorship, Anchor record codec (compiled as-is)
  $root/messenger/dna_api.c
  $root/messenger/dht/client/dna_profile.c
  # BIP39 words -> the Messages KEM keys (nc_keys_from_words)
  $root/shared/crypto/key/bip39/bip39.c
  $root/shared/crypto/key/bip39/bip39_pbkdf2.c
  $root/shared/crypto/key/bip39/seed_derivation.c
  $root/shared/crypto/sign/qgp_signature.c
  $root/shared/crypto/enc/qgp_aes.c
  $root/shared/crypto/enc/aes_keywrap.c
  # nodus client (package (c1) compile set, scripts/check-nodus-client-wasm.sh)
  $root/nodus/src/client/nodus_client.c
  $root/nodus/src/transport/nodus_tcp.c
  $root/nodus/src/protocol/nodus_tier2.c
  $root/nodus/src/protocol/nodus_cbor.c
  $root/nodus/src/protocol/nodus_wire.c
  $root/nodus/src/core/nodus_value.c
  $root/nodus/src/crypto/nodus_sign.c
  $root/nodus/src/crypto/nodus_identity.c
  $root/nodus/src/crypto/nodus_channel_crypto.c
  $root/nodus/src/nodus_log_shim.c
  # the shared SPEND builder (package (c2)) and the envelope codecs
  $root/nodus/src/client/nodus_v2_spend.c
  # the shared staking builder (nodus-cli v2-envelope stake|delegate|
  # undelegate, 0.1.29)
  $root/nodus/src/client/nodus_v2_stake.c
  # the shared chain-name registration builder (nodus-cli name register,
  # HF-4). NOT in the native vector (build-nodus-send-native-vector.sh):
  # its section of nodus-send-wasm.c is networked-build only.
  $root/nodus/src/client/nodus_v2_name.c
  # the shared general-multisig library (nodus-cli msig address / spend
  # --msig / msig sign / msig combine) and the descriptor + address codec
  # it calls — the wallet's vaults (nodus-send-wasm.c "VAULTS"). NOT in the
  # native vector: that section is networked-build only.
  $root/nodus/src/client/nodus_v2_msig.c
  $root/shared/dnac/msig_wire.c
  # the EVM leg + CORE EVMFUND call bytes (smart contracts, Nodus EVM;
  # nodus-send-wasm.c "SMART CONTRACTS"). NOT in the native vector: that
  # section is networked-build only.
  $root/shared/dnac/evm_call_wire.c
  # the shared EVM envelope builder (nodus-cli evm's; Nodus EVM Faz 4) — NOT in
  # the native vector either
  $root/nodus/src/client/nodus_v2_evm.c
  $root/shared/dnac/env_wire.c
  $root/shared/dnac/env_preflight.c
  $root/shared/dnac/res_meter.c
  $root/shared/dnac/effect_wire.c
  # the genesis claim codec (nodus-cli v2-claim's) and the tagged empty
  # roots it references
  $root/shared/dnac/manifest_wire.c
  $root/shared/dnac/ledger_roots_v2.c
  # shared crypto (qgp_platform_<os>.c is NOT linked: nodus-send-wasm.c
  # defines qgp_platform_random and qgp_secure_memzero)
  $root/shared/crypto/hash/qgp_sha3.c
  # Keccak-256: nodus_v2_evm.c nodus_v2_evm_create_address (the CREATE
  # address a receipt's "cr" is checked against, nsw_evm_built_created)
  $root/shared/crypto/hash/keccak256.c
  $root/shared/crypto/hash/hkdf_sha3.c
  $root/shared/crypto/utils/qgp_random.c
  $root/shared/crypto/utils/qgp_fingerprint.c
  $root/shared/crypto/sign/qgp_dilithium.c
  $root/shared/crypto/sign/dsa/sign.c
  $root/shared/crypto/sign/dsa/packing.c
  $root/shared/crypto/sign/dsa/polyvec.c
  $root/shared/crypto/sign/dsa/poly.c
  $root/shared/crypto/sign/dsa/ntt.c
  $root/shared/crypto/sign/dsa/rounding.c
  $root/shared/crypto/sign/dsa/reduce.c
  $root/shared/crypto/sign/dsa/fips202.c
  $root/shared/crypto/sign/dsa/symmetric-shake.c
  $root/shared/crypto/enc/qgp_kyber.c
  $root/shared/crypto/enc/kyber_r3_legacy.c
  $root/shared/crypto/enc/qgp_mlkem.c
  $root/shared/crypto/enc/kem/cbd.c
  $root/shared/crypto/enc/kem/fips202.c
  $root/shared/crypto/enc/kem/indcpa.c
  $root/shared/crypto/enc/kem/kem.c
  $root/shared/crypto/enc/kem/ntt.c
  $root/shared/crypto/enc/kem/poly.c
  $root/shared/crypto/enc/kem/polyvec.c
  $root/shared/crypto/enc/kem/reduce.c
  $root/shared/crypto/enc/kem/symmetric-shake.c
  $root/shared/crypto/enc/kem/verify.c
)

exports_common=(
  nsw_error nsw_seed_buf nsw_req_reset nsw_req_add_coin
  nsw_out_seed_buf nsw_out_seed_load nsw_offline_build
  nsw_built_env nsw_built_env_len nsw_built_intent nsw_built_wire
  nsw_built_chain nsw_built_recipient nsw_built_amount nsw_built_fee
  nsw_built_change nsw_built_expiry nsw_built_n_in nsw_built_in
  nsw_net_reset nsw_net_set_chain nsw_net_add_endpoint nsw_net_add_pin
  nsw_unlock nsw_identify nsw_connect
  nsw_balance nsw_list nsw_build_and_sign nsw_req_env_alloc
  nsw_submit nsw_scan nsw_tick nsw_cancel nsw_lock
  nsw_fingerprint nsw_chain_hex nsw_bal_total nsw_bal_spendable
  nsw_list_tip nsw_list_truncated nsw_list_count nsw_list_nul
  nsw_list_amount nsw_scan_tip nsw_scan_height nsw_scan_found
  # genesis claim (0.1.26)
  nsw_claim_reset nsw_claim_set_manifest nsw_claim_add_leaf nsw_claim_seal
  nsw_claim_offline_build nsw_claim_status nsw_claim_build nsw_claim_submit
  nsw_claim_found nsw_claim_window nsw_claim_claimed nsw_claim_amount
  nsw_claim_tip nsw_claim_start nsw_claim_end nsw_claim_output
  nsw_claim_built_bytes nsw_claim_built_len nsw_claim_built_id
  nsw_claim_built_nullifier nsw_claim_built_output nsw_claim_built_recipient
  nsw_claim_built_chain nsw_claim_built_amount nsw_claim_built_leaf
  # staking (0.1.29)
  nsw_built_op nsw_built_commission nsw_stake_offline_build
  nsw_const_min_delegation nsw_const_self_stake nsw_const_commission_max
  nsw_const_undelegate_lock_epochs nsw_const_epoch_length
  nsw_validators nsw_val_count nsw_val_truncated nsw_val_fp nsw_val_self
  nsw_val_delegated nsw_val_commission nsw_val_status
  # delegator slots per validator ("N/<cap>"; -1 = an older node, unknown)
  nsw_val_delegators nsw_const_max_delegators
  nsw_delegations nsw_del_count nsw_del_fp nsw_del_amount nsw_del_block
  nsw_stake_build
  # HF-4 (design docs/plans/2026-10-02-onchain-names-design.md rev 4 §1.6,
  # §2 "Clients"): the rule-set generation the node runs, chain names and a
  # name owner's signed profile address. nsw_ruleset_info, nsw_name_lookup,
  # nsw_name_of and nsw_profile_address wait on the network (ccall
  # { async: true }); nsw_name_ok and the getters do not.
  nsw_name_ok nsw_ruleset_info nsw_ri_gen nsw_ri_tip nsw_ri_h
  nsw_name_lookup nsw_name_of nsw_name_found nsw_name_owner nsw_name_name
  nsw_name_registered nsw_name_committed
  nsw_profile_address nsw_profile_addr
  # HF-4 chain-name registration (nodus-cli name register over the shared
  # builder nodus_v2_name.c). nsw_name_prices and nsw_name_build wait on
  # the network (ccall { async: true }); nsw_name_offline_build (parity)
  # and the getters do not.
  nsw_built_name nsw_built_price nsw_name_offline_build
  nsw_name_prices nsw_np_price nsw_np_sched_count nsw_np_sched_param
  nsw_np_sched_value nsw_np_sched_effective nsw_name_build
  # VAULTS — general multisig (nodus-send-wasm.c "VAULTS"). Waiting on the
  # network (ccall { async: true }): nsw_msig_member_add, nsw_msig_balance,
  # nsw_msig_scan, nsw_msig_build, nsw_msig_review, nsw_msig_submit. Every
  # other one below never reaches emscripten_sleep.
  nsw_msig_member_reset nsw_msig_member_count nsw_msig_member_add_self
  nsw_msig_member_add nsw_msig_create nsw_msig_load nsw_msig_addr
  nsw_msig_desc_hex nsw_msig_m nsw_msig_n nsw_msig_member nsw_msig_is_member
  nsw_msig_balance nsw_msig_bal_total nsw_msig_bal_spendable
  nsw_msig_coins_reset nsw_msig_coin_add nsw_msig_scan nsw_msig_scan_next
  nsw_msig_scan_tip nsw_msig_coins_full nsw_msig_coin_count nsw_msig_coin_id
  nsw_msig_coin_amount nsw_msig_coin_unlock nsw_msig_coin_height
  nsw_msig_event_count nsw_msig_event_height nsw_msig_event_dir
  nsw_msig_event_amount nsw_msig_event_id
  nsw_msig_prop_in nsw_msig_prop_chain nsw_msig_prop_tip nsw_msig_prop_signers
  nsw_msig_prop_digest nsw_msig_prop_env nsw_msig_text nsw_msig_build
  nsw_msig_review nsw_msig_rv_ok nsw_msig_rv_expired nsw_msig_rv_member
  nsw_msig_rv_vault nsw_msig_rv_m nsw_msig_rv_n nsw_msig_rv_k nsw_msig_rv_fee
  nsw_msig_rv_expiry nsw_msig_rv_now nsw_msig_rv_intent nsw_msig_rv_n_in
  nsw_msig_rv_in nsw_msig_rv_n_out nsw_msig_rv_out_owner
  nsw_msig_rv_out_amount nsw_msig_rv_out_change
  nsw_msig_sign nsw_msig_sig_reset nsw_msig_sig_add nsw_msig_sig_count
  nsw_msig_sig_signer nsw_msig_submit nsw_msig_intent nsw_msig_wire
  # SMART CONTRACTS — the EVM domain (nodus-send-wasm.c "SMART CONTRACTS").
  # Waiting on the network (ccall { async: true }): nsw_evm_call,
  # nsw_evm_create, nsw_evm_deposit, nsw_evm_withdraw, nsw_evm_redeem and
  # the §18 read nsw_evm_query. The settings, request, query buffer / JSON
  # and getters never reach emscripten_sleep.
  nsw_evm_net_set nsw_evm_available nsw_evm_data_alloc nsw_evm_access_reset
  nsw_evm_access_add nsw_evm_set_decl nsw_evm_set_estimate nsw_evm_generation
  nsw_evm_query_buf nsw_evm_query nsw_evm_query_json
  nsw_evm_call nsw_evm_create nsw_evm_deposit nsw_evm_withdraw nsw_evm_redeem
  nsw_evm_built_op nsw_evm_built_to nsw_evm_built_value nsw_evm_built_gas
  nsw_evm_built_nonce nsw_evm_built_units nsw_evm_built_amount
  nsw_evm_built_dest nsw_evm_built_ticket nsw_evm_built_data_len
  # the CREATE address of the signed deployment (red-team 1 F11): the
  # receipt's "cr" is compared with it
  nsw_evm_built_created
  # the OFFLINE EVM build (0.1.64): no node, every network fact given; the
  # EVM leg's identity must equal the compiled one. Never waits.
  nsw_evm_offline_build
  # Messages (NC-4b, connect/nc_wasm.c), all run through the wallet's one
  # queue by src/connect/core.js. The ones that wait on the network (every
  # one below except nc_error, nc_result, nc_words_alloc, nc_salt_pick,
  # nc_day_today, nc_lock, nc_profile_load, the three nc_hist_* and the
  # codec nc_group_* below — but INCLUDING the four G3 network ones named
  # there — and except nc_unlock, which only derives keys) are called with
  # ccall
  # { async: true }; nc_unlock is too (harmless for a call that does not
  # suspend).
  nc_error nc_result nc_words_alloc nc_unlock
  nc_profile_get nc_profile_load nc_profile_update
  nc_requests_get nc_request_new nc_request_approve nc_request_withdraw
  nc_salt_get nc_salt_pick nc_salt_reconcile
  nc_contacts_get nc_contacts_add
  nc_day_today nc_outbox_send nc_outbox_get nc_outbox_get_days
  nc_ack_send nc_ack_get
  nc_hist_key nc_hist_encrypt nc_hist_decrypt
  # groups codec (G2, connect/nc_wasm.c "groups codec"): every one of THESE
  # is synchronous and pure — no network, never reaches emscripten_sleep. The
  # ones without session keys (nc_group_addr_str, nc_group_salt,
  # nc_group_record_read, nc_group_accept, nc_group_json_read) run outside
  # the op bracket like nc_salt_pick; the others enter it like nc_hist_*.
  nc_group_addr_str nc_group_salt
  nc_group_kp_new nc_group_kp_read
  nc_group_record_new nc_group_record_read
  nc_group_head_new nc_group_head_read
  nc_group_msg_new nc_group_bucket_read
  nc_group_invite nc_group_accept nc_group_welcome nc_group_json_read
  # groups G3 (connect/nc_wasm.c "groups (package G3)"). Synchronous, no
  # session, outside the op bracket: nc_group_in_alloc (the heap input
  # buffer), nc_group_random, nc_group_leave. WAIT ON THE NETWORK (inside
  # the bracket, ccall { async: true }): nc_group_get, nc_group_put,
  # nc_group_bucket_send, nc_group_bucket_fetch.
  nc_group_in_alloc nc_group_random nc_group_leave
  nc_group_get nc_group_put nc_group_bucket_send nc_group_bucket_fetch
  nc_lock
)
exports_test=(nsw_test_random_buf nsw_test_random_load nsw_test_pins_tuple nsw_test_gen_match
  nsw_test_msig_member_add_pk nsw_test_msig_build nsw_test_msig_review
  nsw_test_msig_consume nsw_test_msig_seed_pk nsw_test_msig_seed_sign
  nsw_test_evm_call_hex nsw_test_evm_call_roundtrip nsw_test_evmfund_roundtrip
  nsw_test_evm_op_weight nsw_test_evm_build nsw_test_evm_create_address
  nsw_test_evm_args_hex)

join_exports() {
  local out="" name
  for name in "$@"; do out="${out:+$out,}\"_$name\""; done
  printf '[%s]' "$out"
}

# build <define> <environment> <output .js/.mjs> <exports...>
build() {
  local define="$1" env="$2" output="$3"; shift 3
  local objdir="$work/obj-${define}-${env}"
  mkdir -p "$objdir"
  local objects=() src obj
  for src in "${sources[@]}"; do
    obj="$objdir/$(echo "$src" | tr '/.' '__').o"
    local extra=()
    # shared/crypto/utils/qgp_fingerprint.c:15 sizes a 16-char digit table
    # without its NUL on purpose (indexed, never used as a string); the
    # clang of emsdk 6.0.10 warns about that form. Silenced for that one
    # file only — shared/ is outside this package.
    case "$src" in */qgp_fingerprint.c) extra=(-Wno-unterminated-string-initialization) ;; esac
    "$EMCC_BIN" -c -O2 -std=gnu11 -Wall -Wextra -Wno-unused-parameter -Werror \
      "${extra[@]}" -D"$define" \
      -I$root/nodus/include -I$root/nodus/src -I$root/shared -I$root/dnac/include \
      -I"$work/inc" -I"$OPENSSL_WASM_PREFIX/include" \
      -I$root/messenger -I$root/messenger/include -Iconnect \
      -I"$JSONC_WASM_PREFIX/include" \
      "$src" -o "$obj"
    objects+=("$obj")
  done
  "$EMCC_BIN" -O2 -Werror "${objects[@]}" \
    "$JSONC_WASM_PREFIX/lib/libjson-c.a" "$OPENSSL_WASM_PREFIX/lib/libcrypto.a" \
    --no-entry \
    -sMODULARIZE=1 -sEXPORT_ES6=1 -sEXPORT_NAME=createNodusSendWasm \
    -sENVIRONMENT="$env" \
    -sASYNCIFY=1 -sASYNCIFY_STACK_SIZE=$ASYNCIFY_STACK \
    -sSTACK_SIZE=1048576 -sINITIAL_MEMORY=67108864 \
    -sALLOW_MEMORY_GROWTH=1 -sMAXIMUM_MEMORY=268435456 \
    -sWEBSOCKET_URL=wss:// -sWEBSOCKET_SUBPROTOCOL=binary \
    -sEXPORTED_FUNCTIONS="$(join_exports "$@")" \
    -sEXPORTED_RUNTIME_METHODS='["ccall","UTF8ToString","HEAPU8","abort"]' \
    -o "$output"
}

if [ "$mode" = release ]; then
  mkdir -p src/nodus
  build NODUS_SEND_RELEASE web src/nodus/send.js "${exports_common[@]}"
  chmod 644 src/nodus/send.js src/nodus/send.wasm
  sha256sum src/nodus/send.wasm src/nodus/send.js
  ls -l src/nodus/send.wasm src/nodus/send.js
else
  out="${NODUS_SEND_PARITY_OUT:-/tmp/nodus-send-parity}"
  case "$(cd "$out" 2>/dev/null && pwd -P || echo "$out")" in
    "$(pwd -P)"/*) echo "build-nodus-send-wasm: parity output must be outside web-wallet/ ($out)" >&2; exit 2 ;;
  esac
  mkdir -p "$out"
  build NODUS_SEND_RELEASE node "$out/send-node.mjs" "${exports_common[@]}"
  build NODUS_SEND_TEST_FIXED_RANDOM node "$out/send-test-node.mjs" "${exports_common[@]}" "${exports_test[@]}"
  ls -l "$out"
fi
