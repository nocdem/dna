#!/bin/bash
# Generate seed corpus files for libFuzzer harnesses
#
# These are minimal valid (or near-valid) inputs to help the fuzzer
# explore the code more efficiently.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORPUS_DIR="$SCRIPT_DIR/corpus"

echo "Generating seed corpus files..."

# =============================================================================
# Offline Queue Corpus
# =============================================================================
# Format: [4-byte count][messages...]
# Message: magic(4) + version(1) + seq_num(8) + timestamp(8) + expiry(8)
#          + sender_len(2) + recipient_len(2) + ciphertext_len(4)
#          + sender + recipient + ciphertext

# Empty queue (count = 0)
printf '\x00\x00\x00\x00' > "$CORPUS_DIR/offline_queue/empty.bin"

# One message with minimal content (count = 1, magic "DNA ", version 2)
printf '\x00\x00\x00\x01' > "$CORPUS_DIR/offline_queue/one_minimal.bin"  # count = 1
printf 'DNA \x02' >> "$CORPUS_DIR/offline_queue/one_minimal.bin"  # magic + version
printf '\x00\x00\x00\x00\x00\x00\x00\x01' >> "$CORPUS_DIR/offline_queue/one_minimal.bin"  # seq_num = 1
printf '\x00\x00\x00\x00\x67\x00\x00\x00' >> "$CORPUS_DIR/offline_queue/one_minimal.bin"  # timestamp
printf '\x00\x00\x00\x00\x68\x00\x00\x00' >> "$CORPUS_DIR/offline_queue/one_minimal.bin"  # expiry
printf '\x00\x04' >> "$CORPUS_DIR/offline_queue/one_minimal.bin"  # sender_len = 4
printf '\x00\x04' >> "$CORPUS_DIR/offline_queue/one_minimal.bin"  # recipient_len = 4
printf '\x00\x00\x00\x08' >> "$CORPUS_DIR/offline_queue/one_minimal.bin"  # ciphertext_len = 8
printf 'test' >> "$CORPUS_DIR/offline_queue/one_minimal.bin"  # sender
printf 'recv' >> "$CORPUS_DIR/offline_queue/one_minimal.bin"  # recipient
printf 'cipherXX' >> "$CORPUS_DIR/offline_queue/one_minimal.bin"  # ciphertext

echo "  - offline_queue: 2 seed files"

# =============================================================================
# Contact Request Corpus
# =============================================================================
# Format: magic(4) + version(1) + timestamp(8) + expiry(8)
#         + fingerprint(129) + name(64) + pubkey(2592) + message(256)
#         + sig_len(2) + signature

# Minimal valid header
printf 'DNAR\x01' > "$CORPUS_DIR/contact_request/header_only.bin"

# Header with timestamp
printf 'DNAR\x01' > "$CORPUS_DIR/contact_request/with_timestamp.bin"
printf '\x00\x00\x00\x00\x67\x00\x00\x00' >> "$CORPUS_DIR/contact_request/with_timestamp.bin"  # timestamp
printf '\x00\x00\x00\x00\x68\x00\x00\x00' >> "$CORPUS_DIR/contact_request/with_timestamp.bin"  # expiry

echo "  - contact_request: 2 seed files"

# =============================================================================
# GSK Packet Corpus
# =============================================================================
# Format: uuid(37) + version(4) + member_count(1) + members + signature

# Minimal header with 0 members
printf '00000000-0000-0000-0000-000000000000\x00' > "$CORPUS_DIR/gsk_packet/header_only.bin"  # UUID (37 bytes)
printf '\x00\x00\x00\x01' >> "$CORPUS_DIR/gsk_packet/header_only.bin"  # version = 1
printf '\x00' >> "$CORPUS_DIR/gsk_packet/header_only.bin"  # member_count = 0

echo "  - gsk_packet: 1 seed file"

# =============================================================================
# Message Decrypt Corpus
# =============================================================================
# Format: magic(8) + version(1) + enc_key_type(1) + recipient_count(1) + msg_type(1)
#         + recipients + nonce + ciphertext + tag + signature

# Minimal header
printf 'PQSIGENC' > "$CORPUS_DIR/message_decrypt/header_only.bin"  # magic
printf '\x08' >> "$CORPUS_DIR/message_decrypt/header_only.bin"  # version 0x08
printf '\x01' >> "$CORPUS_DIR/message_decrypt/header_only.bin"  # enc_key_type
printf '\x01' >> "$CORPUS_DIR/message_decrypt/header_only.bin"  # recipient_count = 1
printf '\x00' >> "$CORPUS_DIR/message_decrypt/header_only.bin"  # msg_type

echo "  - message_decrypt: 1 seed file"

# =============================================================================
# Profile JSON Corpus
# =============================================================================
# Valid JSON profile

cat > "$CORPUS_DIR/profile_json/valid_profile.json" << 'EOF'
{"display_name":"Alice","bio":"Hello world","avatar_hash":"abc123","location":"Earth","website":"https://example.com","created_at":1700000000,"updated_at":1700000001}
EOF

cat > "$CORPUS_DIR/profile_json/empty_profile.json" << 'EOF'
{"display_name":"","bio":"","avatar_hash":"","location":"","website":""}
EOF

cat > "$CORPUS_DIR/profile_json/minimal.json" << 'EOF'
{}
EOF

echo "  - profile_json: 3 seed files"

# =============================================================================
# Base58 Corpus
# =============================================================================
# Valid base58 strings (no 0, O, I, l characters)

echo -n "5Kd3NBUAdUnhyzenEwVLy9pBKxSwXvE9FMPyR4UKZvpe6E3AgLr" > "$CORPUS_DIR/base58/valid_privkey.txt"
echo -n "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" > "$CORPUS_DIR/base58/valid_address.txt"
echo -n "abc123" > "$CORPUS_DIR/base58/short.txt"
echo -n "" > "$CORPUS_DIR/base58/empty.txt"

echo "  - base58: 4 seed files"

echo ""
echo "Corpus generation complete!"
echo "Total: $(find "$CORPUS_DIR" -type f | wc -l) seed files"
