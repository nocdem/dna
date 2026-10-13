#!/usr/bin/env bash
# Nodus Connect thin core: C -> WebAssembly (packages NC-2 / NC-4b of
# docs/plans/2026-09-24-web-connect-design.md rev 5, §1.1; governing decision
# docs/plans/decisions/2026-09-30-nodus-connect-thin-core.md).
#
# Since NC-4b there is NO separate Messages module. The thin core
# (web-wallet/connect/nc_*.c, JSON exports connect/nc_wasm.c) is linked into
# the wallet's one module, src/nodus/send.wasm, and runs on that module's
# tier-2 session: a second module would open a second session of the same
# identity, and the node closes the other one (nodus_auth.c:95-116). The
# standalone test build this script used to produce (its own session, in
# /tmp/nodus-connect-wasm) is retired, and nc_wasm.c no longer compiles
# without the send module (#error).
#
# This script builds the one module: every argument is passed through.
#   build-connect-wasm.sh           the shipped module -> src/nodus/send.{js,wasm}
#   build-connect-wasm.sh parity    the node builds for the parity tests
# The source lists and the export lists live in build-nodus-send-wasm.sh —
# including the P1 rules (connect/nc_payload.c, nc_rules.c, nc_rules_json.c),
# compiled into the parity TEST build only, with its nc_rule_in_alloc /
# nc_rule_test exports; the shipped module has none. Their JSON layer
# (connect/nc_jsjson.c) and the P7 stage 1 state codec (connect/nc_state.c,
# exports nc_state_project / nc_state_load) are in the shipped module.
# Native unit tests of the library: connect/tests/ (CMake).
set -euo pipefail
exec bash "$(dirname "$0")/build-nodus-send-wasm.sh" "$@"
