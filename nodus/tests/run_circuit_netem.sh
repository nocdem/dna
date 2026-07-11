#!/usr/bin/env bash
# Circuit latency under emulated packet loss / jitter — PQ-VoIP Faz 0.
#
# Runs build/circuit_latency_probe inside a throwaway network namespace with
# `tc netem` applied to THAT namespace's own loopback, so the host's `lo` is
# never touched. Sweeps a few loss/jitter profiles matching a Turkish-mobile
# target and prints each profile's one-way latency distribution + verdict.
#
# Requires root (netns + tc). Run it yourself:
#     ! sudo bash /opt/dna/nodus/tests/run_circuit_netem.sh
#
# Pre-registered kill-criterion (from the /council review): p95 one-way > 250 ms
# ⇒ TCP-MVP is not viable, promote the UDP fast path (Faz C) ahead of libopus.
#
# NOTE (baseline finding, no netem): the client read thread polls every 100 ms
# (nodus_client.c: nodus_tcp_poll(tcp, 100)), which alone adds up to ~100 ms
# one-way latency for a 50 fps stream. netem below STACKS on top of that floor.
set -u

PROBE="${PROBE:-/opt/dna/nodus/build/circuit_latency_probe}"
NS="cvoip_probe_$$"
DEV="lo"

if [[ $EUID -ne 0 ]]; then echo "must run as root (netns + tc)"; exit 1; fi
if [[ ! -x "$PROBE" ]]; then echo "probe not found/built: $PROBE"; exit 1; fi
command -v tc >/dev/null || { echo "tc (iproute2) not found"; exit 1; }

cleanup() { ip netns del "$NS" 2>/dev/null; }
trap cleanup EXIT

ip netns add "$NS"
ip netns exec "$NS" ip link set "$DEV" up

# Per-hop netem profiles: "label;delay;jitter;loss". The in-process path is
# client→srvA→srvB→client2 = 3 loopback hops, so each frame is impaired 3×
# (representative of a 3-hop relay). Keep per-hop numbers modest.
PROFILES=(
  "clean;0ms;0ms;0%"
  "good-wifi;10ms;5ms;0.5%"
  "mobile-4g;25ms;15ms;1%"
  "mobile-congested;40ms;25ms;3%"
)

echo "=== netem circuit latency sweep (netns=$NS, 3-hop in-process path) ==="
for p in "${PROFILES[@]}"; do
  IFS=';' read -r label delay jitter loss <<<"$p"
  echo
  echo "### profile: $label  (per-hop: delay=$delay jitter=$jitter loss=$loss)"
  ip netns exec "$NS" tc qdisc del dev "$DEV" root 2>/dev/null
  if [[ "$delay" != "0ms" || "$loss" != "0%" ]]; then
    ip netns exec "$NS" tc qdisc add dev "$DEV" root netem \
        delay "$delay" "$jitter" distribution normal loss "$loss"
  fi
  ip netns exec "$NS" env PROBE_FRAMES="${PROBE_FRAMES:-500}" \
      PROBE_INTERVAL_MS="${PROBE_INTERVAL_MS:-20}" \
      PROBE_FRAME_BYTES="${PROBE_FRAME_BYTES:-160}" \
      "$PROBE" 2>/dev/null | grep -E "sent=|one-way|VERDICT|no frames"
done

echo
echo "=== sweep complete ==="
echo "Reminder: subtract nothing — the numbers already include the ~100 ms"
echo "client-poll floor. If even 'good-wifi' p95 > 250 ms, that floor (not the"
echo "network) is the first thing to fix before any voice MVP."
