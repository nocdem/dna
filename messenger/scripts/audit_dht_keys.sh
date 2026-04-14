#!/usr/bin/env bash
# audit_dht_keys.sh — static grep audit for unsalted DHT key producers
#
# Phase 6 / CORE-04. Exit 0 = clean, 1 = unsalted producer found.
#
# How it works:
#   1. Find every file under messenger/dht/ and messenger/transport/ that
#      calls nodus_ops_put*. These are the DHT key producers.
#   2. Skip files in the WHITELIST (intentionally public / non-sensitive
#      surfaces, e.g. keyserver, profiles, group metadata blobs, salt
#      agreement itself, the nodus_ops wrapper).
#   3. For every remaining file, require at least one mention of "salt" —
#      if there is none, the file is producing deterministic / unsalted
#      DHT keys and is a privacy leak.
#
# Today (Wave 0) this MUST report dna_group_outbox.c as [FAIL no-salt] and
# exit 1. Plan 04 will add salt threading to that file and the script will
# exit 0.

set -euo pipefail
cd "$(dirname "$0")/.."

# Whitelist: known-public DHT keys that intentionally don't use salts.
#  - keyserver_*: public name/profile registry (intentionally lookupable)
#  - dht_profile.c: public profile blob
#  - dht_addressbook.c, dht_grouplist.c: per-identity public lists
#  - dht_geks.c, dht_gek_storage.c: GEK distribution to known group members
#  - dht_groups.c: public group metadata
#  - dht_message_backup.c: encrypted backup at owner-derived key
#  - dht_bootstrap_registry.c: cluster bootstrap discovery
#  - dna_wall*: public wall posts/comments/likes
#  - dht_salt_agreement.c: the salt agreement protocol itself
#  - dna_channels.c / dht_channel_subscriptions.c: channels feature (disabled)
#  - nodus_ops.{c,h}: the producer wrapper itself, not a key derivation site
WHITELIST='keyserver_publish.c|keyserver_names.c|keyserver_profiles.c|dht_profile.c|dht_addressbook.c|dht_grouplist.c|dht_geks.c|dht_gek_storage.c|dht_groups.c|dht_message_backup.c|dht_bootstrap_registry.c|dna_wall|dht_salt_agreement.c|dna_channels\.|dht_channel_subscriptions\.c|nodus_ops\.[ch]'

echo "=== DHT key producer audit ==="
FAIL=0

PRODUCERS=$(grep -rln 'nodus_ops_put' dht/ transport/ 2>/dev/null || true)
for f in $PRODUCERS; do
  base=$(basename "$f")
  if echo "$base" | grep -Eq "$WHITELIST"; then
    echo "[SKIP whitelist] $f"
    continue
  fi
  if ! grep -qE 'salt' "$f"; then
    echo "[FAIL no-salt] $f"
    FAIL=1
  else
    echo "[OK salted]    $f"
  fi
done

exit $FAIL
