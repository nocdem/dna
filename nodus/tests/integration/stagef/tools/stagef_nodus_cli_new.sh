#!/usr/bin/env bash
# stagef_nodus_cli_new.sh — the harness wrapper (stagef_nodus_cli.sh: pin,
# chain id, own-node tools) with the NEW nodus-cli as the real binary.
#
# The OLD/NEW upgrade scenarios (test_cmt_hf1_gas_upgrade.sh,
# test_cmt_hf2_gov_power.sh, test_cmt_hf3_block_bounds.sh,
# test_cmt_hf4_names.sh, test_cmt_evm.sh) name the NEW nodus-cli by
# STAGEF_NODUSCLI_BIN_NEW. They called that binary directly, so its calls got no
# `--pin` and no `--chain-id` (a 4001 session needs both) and a chain-config
# propose got no `--config`. After their capability probes they use this file
# as $NEW_CLI instead: it runs stagef_nodus_cli.sh with
# STAGEF_NODUSCLI_REAL = $STAGEF_NODUSCLI_BIN_NEW. Nothing else changes.
# (The OLD nodus-cli speaks the removed handshake and cannot cross the change.)
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
: "${STAGEF_NODUSCLI_BIN_NEW:?STAGEF_NODUSCLI_BIN_NEW is not set}"
export STAGEF_NODUSCLI_REAL="$STAGEF_NODUSCLI_BIN_NEW"
exec "$HERE/stagef_nodus_cli.sh" "$@"
