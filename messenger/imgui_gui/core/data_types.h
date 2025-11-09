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

#endif // DATA_TYPES_H
