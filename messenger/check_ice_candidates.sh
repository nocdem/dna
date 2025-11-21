#!/bin/bash
# Check if ICE candidates are published in DHT for a given fingerprint

if [ -z "$1" ]; then
    echo "Usage: $0 <peer_fingerprint>"
    echo "Example: $0 88a2f89d6999eda9..."
    exit 1
fi

FINGERPRINT="$1"

echo "=== ICE Candidate DHT Lookup ==="
echo "Peer fingerprint: $FINGERPRINT"
echo ""
echo "DHT key input: ${FINGERPRINT}:ice_candidates"
echo ""

# Calculate SHA3-512 hash using Python
HASH=$(python3 -c "
import hashlib
key_input = '${FINGERPRINT}:ice_candidates'
hash_obj = hashlib.sha3_512(key_input.encode())
print(hash_obj.hexdigest())
")

echo "SHA3-512 hash (128 hex chars): $HASH"
echo ""
echo "Note: OpenDHT will further hash this to 160-bit InfoHash (40 hex chars)"
echo ""

# Try to query DHT (requires dna_messenger_imgui running)
echo "To check if candidates exist, the peer must have:"
echo "  1. Started dna_messenger_imgui"
echo "  2. ICE initialized successfully (check peer logs)"
echo "  3. Published candidates via ice_init_persistent()"
echo ""
echo "Check peer's log for:"
echo "  [ICE] Candidates published to DHT"
