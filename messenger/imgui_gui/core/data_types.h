#ifndef DATA_TYPES_H
#define DATA_TYPES_H

#include <string>

// Message data structure
struct Message {
    std::string sender;
    std::string content;
    std::string timestamp;
    bool is_outgoing;
};

// Contact data structure
struct Contact {
    std::string name;
    std::string address;
    bool is_online;
};

#endif // DATA_TYPES_H
