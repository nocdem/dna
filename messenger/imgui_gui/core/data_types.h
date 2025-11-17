#ifndef DATA_TYPES_H
#define DATA_TYPES_H

#include <string>

// Message status enumeration
enum MessageStatus {
    STATUS_PENDING = 0,  // Sending in progress (clock icon)
    STATUS_SENT = 1,     // Successfully sent (checkmark)
    STATUS_FAILED = 2    // Send failed (error icon + retry)
};

// Message data structure
struct Message {
    std::string sender;
    std::string content;
    std::string timestamp;
    bool is_outgoing;
    MessageStatus status;  // Delivery status
};

// Contact data structure
struct Contact {
    std::string name;
    std::string address;
    bool is_online;
};

// Group data structure
struct Group {
    int local_id;             // Local database ID
    std::string group_uuid;   // Global UUID
    std::string name;         // Group name
    std::string creator;      // Creator identity
    int member_count;         // Number of members
    uint64_t created_at;      // Creation timestamp
    uint64_t last_sync;       // Last DHT sync timestamp
};

// Group invitation structure
struct GroupInvitation {
    std::string group_uuid;   // UUID v4 (36 chars)
    std::string group_name;   // Group display name
    std::string inviter;      // Who invited this user
    uint64_t invited_at;      // Unix timestamp when invited
    int status;               // 0=pending, 1=accepted, 2=rejected
    int member_count;         // Number of members in group
};

#endif // DATA_TYPES_H
