#!/bin/bash
# Manual build script for P2P transport (temporary until CMake is fixed)

set -e

echo "Building P2P Transport Layer..."

# Compile P2P transport
gcc -c -I../dht -I. p2p_transport.c -o p2p_transport.o

# Link test program
gcc -I../dht -I. test_p2p_basic.c p2p_transport.o ../dht/build/libdht_lib.a \
    -lopendht -lssl -lcrypto -lpthread -lstdc++ -o test_p2p_basic

echo "✓ Build complete!"
echo "Run: ./test_p2p_basic <bootstrap_node>"
echo "Example: ./test_p2p_basic 154.38.182.161:4000"
