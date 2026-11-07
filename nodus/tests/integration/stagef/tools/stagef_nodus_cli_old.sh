#!/usr/bin/env bash
# stagef_nodus_cli_old.sh — the harness wrapper (stagef_nodus_cli.sh: pin,
# chain id, own-node tools) with the OLD nodus-cli as the real binary.
#
# The mirror of stagef_nodus_cli_new.sh. test_cmt_evm.sh names the OLD nodus-cli
# by STAGEF_NODUSCLI_BIN_OLD. After its capability probes it uses this file as
# $OLD_CLI: it runs stagef_nodus_cli.sh with
# STAGEF_NODUSCLI_REAL = $STAGEF_NODUSCLI_BIN_OLD, so the OLD CLI's calls that
# dial a harness node get `--pin` and `--chain-id` (a 4001 session needs both)
# and a chain-config propose gets `--config`. Nothing else changes.
# It works only for an OLD build that is itself after the 4001 change (nodus
# 0.26.33, commit ba3d90060); an older nodus-cli speaks the removed handshake
# and cannot cross it (README "Cannot cross the change").
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
: "${STAGEF_NODUSCLI_BIN_OLD:?STAGEF_NODUSCLI_BIN_OLD is not set}"
export STAGEF_NODUSCLI_REAL="$STAGEF_NODUSCLI_BIN_OLD"
exec "$HERE/stagef_nodus_cli.sh" "$@"
