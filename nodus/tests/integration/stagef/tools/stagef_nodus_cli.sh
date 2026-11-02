#!/usr/bin/env bash
# stagef_nodus_cli.sh — nodus-cli for the harness, with the 4001 trust added.
#
# Approved 4001 plan section 3.10 / 4.4: a 4001 session needs a trusted node
# list and a chain id before it starts. The built-in values are the testnet's;
# the harness's nodes are not on it. This wrapper is STAGEF_NODUSCLI_BIN's
# default (stagef_env.sh). For a call that names a harness node by its client
# port (-p 14001 + (n-1)*10) it puts, BEFORE the command,
#     --pin <node n's identity/nodus.fp>   --chain-id <$BASE_DIR/v2_chain_id>
# in front of the command and runs the real binary
# ($STAGEF_NODUSCLI_REAL, default nodus/build/nodus-cli). Nothing else about
# the call changes, except:
#   chain-config propose   is an own-node tool (design D9): it talks to the
#                          node's own witness.sock, found from that node's
#                          config. The wrapper appends
#                          --config <the config of the node whose key is
#                          named by -i> (the proposer's own node); without -i
#                          the node of the -p port.
# A call that does not name a harness port (a usage probe on PROBE_PORT, whoami,
# msig address, ...) or a run without $BASE_DIR/v2_chain_id (before the
# bring-up wrote it) is passed through untouched.
#
# What it does NOT do: it does not turn a call that dials a node with that
# node's own key into anything else (a reflection is refused by the node, the
# call fails as it should); those calls are listed in the README.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/../stagef_env.sh"
REAL="${STAGEF_NODUSCLI_REAL:-$STAGEF_REPO_ROOT/nodus/build/nodus-cli}"

globals=()
port="" ident=""
while [ $# -gt 0 ]; do
    case "$1" in
        -s) globals+=("$1" "$2"); shift 2 ;;
        -p) globals+=("$1" "$2"); port="$2"; shift 2 ;;
        -i) globals+=("$1" "$2"); ident="$2"; shift 2 ;;
        --pin|--chain-id)    # already given by the caller: pass everything through
            exec "$REAL" "${globals[@]}" "$@" ;;
        -*) globals+=("$1"); shift ;;
        *) break ;;
    esac
done

# node index of a harness client port, or empty
node_of_port() {
    local p="$1" n
    case "$p" in ''|*[!0-9]*) return 0 ;; esac
    [ "$p" -ge 14001 ] || return 0
    [ $(( (p - 14001) % 10 )) -eq 0 ] || return 0
    n=$(( (p - 14001) / 10 + 1 ))
    [ "$n" -ge 1 ] && [ "$n" -le "${STAGEF_COMMITTEE_SIZE:-7}" ] || [ "$n" -le 21 ] || return 0
    echo "$n"
}
# node index whose identity dir is $1, or empty
node_of_ident() {
    local d="$1" n
    [ -n "$d" ] || return 0
    for n in $(seq 1 21); do
        [ "$(stagef_node_dir "$n")/identity" = "$d" ] && { echo "$n"; return 0; }
    done
}

n="$(node_of_port "$port")"
chain_file="${BASE_DIR:-}/v2_chain_id"
if [ -z "$n" ] || [ ! -s "$chain_file" ] || [ ! -s "$(stagef_node_dir "$n")/identity/nodus.fp" ]; then
    exec "$REAL" "${globals[@]}" "$@"
fi
fp="$(cat "$(stagef_node_dir "$n")/identity/nodus.fp")"
chain="$(cat "$chain_file")"

rest=("$@")
if [ "${rest[0]:-}" = "chain-config" ] && [ "${rest[1]:-}" = "propose" ]; then
    owner="$(node_of_ident "$ident")"
    o="${owner:-$n}"
    # The harness gives every node its data dir on the command line (-d), not
    # in nodus.json, so the node config does not name witness.sock's directory.
    # The tool reads only identity_path and data_path: write that, per node.
    tool_cfg="$(stagef_node_dir "$o")/cli-tool.json"
    printf '{"identity_path": "%s", "data_path": "%s"}\n' \
        "$(stagef_node_dir "$o")/identity" "$(stagef_node_dir "$o")/data" > "$tool_cfg"
    rest+=(--config "$tool_cfg")
fi
exec "$REAL" "${globals[@]}" --pin "$fp" --chain-id "$chain" "${rest[@]}"
