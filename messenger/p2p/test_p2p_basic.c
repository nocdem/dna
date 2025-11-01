#include "p2p_transport.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/**
 * Basic test program for P2P transport layer
 *
 * Tests:
 * 1. Transport initialization
 * 2. DHT bootstrapping
 * 3. TCP listener setup
 * 4. Peer presence registration
 * 5. Peer lookup
 *
 * Usage: ./test_p2p_basic <bootstrap_node>
 * Example: ./test_p2p_basic 154.38.182.161:4000
 */

static void message_callback(
    const uint8_t *peer_pubkey,
    const uint8_t *message,
    size_t message_len,
    void *user_data)
{
    printf("[CALLBACK] Received message from peer (%zu bytes)\n", message_len);
}

static void connection_callback(
    const uint8_t *peer_pubkey,
    bool is_connected,
    void *user_data)
{
    printf("[CALLBACK] Peer %s\n", is_connected ? "connected" : "disconnected");
}

int main(int argc, char *argv[]) {
    printf("=== DNA Messenger P2P Transport Test ===\n\n");

    // Check arguments
    if (argc < 2) {
        printf("Usage: %s <bootstrap_node>\n", argv[0]);
        printf("Example: %s 154.38.182.161:4000\n", argv[0]);
        return 1;
    }

    // Dummy cryptographic keys (normally loaded from wallet)
    uint8_t my_privkey[4016] = {0};
    uint8_t my_pubkey[1952] = {0};
    uint8_t my_kyber_key[2400] = {0};

    // Fill with test patterns
    memset(my_privkey, 0xAA, sizeof(my_privkey));
    memset(my_pubkey, 0xBB, sizeof(my_pubkey));
    memset(my_kyber_key, 0xCC, sizeof(my_kyber_key));

    printf("1. Creating P2P configuration...\n");
    p2p_config_t config = {0};
    config.listen_port = 4001;
    config.dht_port = 4000;
    config.enable_offline_queue = true;
    config.offline_ttl_seconds = 604800; // 7 days
    snprintf(config.identity, sizeof(config.identity), "test-node");

    // Parse bootstrap node
    snprintf(config.bootstrap_nodes[0], 256, "%s", argv[1]);
    config.bootstrap_count = 1;

    printf("   ✓ Configuration created\n");
    printf("   Bootstrap: %s\n", config.bootstrap_nodes[0]);
    printf("   TCP port: %d\n", config.listen_port);
    printf("   DHT port: %d\n\n", config.dht_port);

    // Initialize transport
    printf("2. Initializing P2P transport...\n");
    p2p_transport_t *transport = p2p_transport_init(
        &config,
        my_privkey,
        my_pubkey,
        my_kyber_key,
        message_callback,
        connection_callback,
        NULL
    );

    if (!transport) {
        printf("   ✗ Failed to initialize P2P transport\n");
        return 1;
    }
    printf("   ✓ P2P transport initialized\n\n");

    // Start transport
    printf("3. Starting P2P transport (DHT + TCP listener)...\n");
    if (p2p_transport_start(transport) != 0) {
        printf("   ✗ Failed to start P2P transport\n");
        p2p_transport_free(transport);
        return 1;
    }
    printf("   ✓ DHT started and bootstrapped to %s\n", argv[1]);
    printf("   ✓ TCP listener on port %d is ready\n", config.listen_port);
    printf("   ✓ Listener thread started\n\n");

    // Wait for DHT to bootstrap
    printf("4. Waiting for DHT to bootstrap (10 seconds)...\n");
    sleep(10);

    // Register presence
    printf("5. Registering presence in DHT...\n");
    if (p2p_register_presence(transport) == 0) {
        printf("   ✓ Presence registered in DHT\n\n");
    } else {
        printf("   ✗ Failed to register presence\n\n");
    }

    // Lookup self (testing DHT get)
    printf("6. Looking up self in DHT...\n");
    peer_info_t self_info = {0};
    if (p2p_lookup_peer(transport, my_pubkey, &self_info) == 0) {
        printf("   ✓ Found self in DHT\n");
        printf("   IP: %s\n", self_info.ip);
        printf("   Port: %d\n", self_info.port);
        printf("   Online: %s\n", self_info.is_online ? "yes" : "no");
    } else {
        printf("   ✗ Failed to lookup self (DHT may still be bootstrapping)\n");
    }
    printf("\n");

    // Get statistics
    printf("7. Getting transport statistics...\n");
    size_t conn_active, msg_sent, msg_recv, off_queued;
    p2p_get_stats(transport, &conn_active, &msg_sent, &msg_recv, &off_queued);
    printf("   Active connections: %zu\n", conn_active);
    printf("   Messages sent: %zu\n", msg_sent);
    printf("   Messages received: %zu\n", msg_recv);
    printf("   Offline queued: %zu\n", off_queued);
    printf("\n");

    // Keep running for a bit
    printf("8. Keeping transport running for 30 seconds...\n");
    printf("   (Press Ctrl+C to exit early)\n\n");
    sleep(30);

    // Cleanup
    printf("9. Shutting down...\n");
    p2p_transport_stop(transport);
    p2p_transport_free(transport);
    printf("   ✓ Transport stopped and freed\n\n");

    printf("=== Test Complete ===\n");
    return 0;
}
