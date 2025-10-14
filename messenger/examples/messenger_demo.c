/*
 * DNA Messenger - Demo Program
 *
 * Automated demo of Phase 3 messenger functionality
 */

#include <stdio.h>
#include <stdlib.h>
#include "../messenger.h"

int main(void) {
    printf("\n");
    printf("================================================================================\n");
    printf(" DNA Messenger - Phase 3 Demo\n");
    printf("================================================================================\n");
    printf("\n");

    // Initialize Alice's messenger
    printf("[1/6] Initializing Alice's messenger...\n");
    messenger_context_t *alice = messenger_init("alice");
    if (!alice) {
        fprintf(stderr, "Failed to initialize Alice's messenger\n");
        return 1;
    }
    printf("\n");

    // Add Bob as contact
    printf("[2/6] Alice adds Bob as contact...\n");
    messenger_add_contact(alice, "bob", NULL);
    printf("\n");

    // Add Charlie as contact
    printf("[3/6] Alice adds Charlie as contact...\n");
    messenger_add_contact(alice, "charlie", NULL);
    printf("\n");

    // List contacts
    printf("[4/6] Alice lists her contacts...\n");
    messenger_list_contacts(alice);

    // Send messages
    printf("[5/6] Alice sends messages...\n\n");
    messenger_send_message(alice, "bob", "Hey Bob! How are you?");
    printf("\n");
    messenger_send_message(alice, "bob", "Want to grab coffee later?");
    printf("\n");
    messenger_send_message(alice, "charlie", "Hi Charlie! Long time no see.");
    printf("\n");

    // List conversations
    printf("[6/6] Alice lists her conversations...\n");
    messenger_list_conversations(alice);

    // List all messages
    printf("[7/6] Alice lists all messages...\n");
    messenger_list_messages(alice, NULL);

    // List messages with Bob
    printf("[8/6] Alice lists messages with Bob...\n");
    messenger_list_messages(alice, "bob");

    //Clean up
    messenger_free(alice);

    printf("================================================================================\n");
    printf(" Demo Complete!\n");
    printf("================================================================================\n");
    printf("\n");
    printf("What happened:\n");
    printf("  ✓ Alice's messenger initialized\n");
    printf("  ✓ Contacts added (Bob, Charlie)\n");
    printf("  ✓ Messages encrypted and stored locally\n");
    printf("  ✓ Conversations tracked\n");
    printf("  ✓ Message history persisted to SQLite database\n");
    printf("\n");
    printf("Database location: ~/.dna/messages.db\n");
    printf("\n");
    printf("Next steps (Phase 4):\n");
    printf("  - Network transport (WebSocket)\n");
    printf("  - Message delivery over network\n");
    printf("  - Offline message queue\n");
    printf("\n");

    return 0;
}
