#ifndef DATA_TYPES_H
#define DATA_TYPES_H

#include <cstdint>
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
    int message_type;      // 0=chat, 1=group_invitation (Phase 6.2)
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

// Feed channel structure
struct FeedChannel {
    std::string channel_id;     // SHA256 hex of channel name
    std::string name;           // Display name (64 chars max)
    std::string description;    // Description (512 chars max)
    std::string creator_fp;     // Creator fingerprint
    uint64_t created_at;        // Creation timestamp
    int post_count;             // Approximate post count
    int subscriber_count;       // Approximate subscriber count
    uint64_t last_activity;     // Latest post timestamp
    int unread_count;           // Unread posts since last view
};

// Feed post structure
struct FeedPost {
    std::string post_id;        // Unique ID: fingerprint_timestamp_random
    std::string channel_id;     // Parent channel
    std::string author_fp;      // Author fingerprint
    std::string author_name;    // Cached display name
    std::string author_avatar;  // Base64 avatar data
    std::string text;           // Post content (2048 chars max)
    uint64_t timestamp;         // Unix timestamp (milliseconds)
    std::string reply_to;       // Parent post_id (empty for top-level)
    int reply_depth;            // 0=post, 1=comment, 2=reply
    int reply_count;            // Number of direct replies
    int upvotes;                // Upvote count
    int downvotes;              // Downvote count
    int user_vote;              // Current user's vote: +1, -1, 0
    bool verified;              // Signature verified
};

#endif // DATA_TYPES_H
