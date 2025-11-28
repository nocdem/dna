package io.cpunk.dna;

public class Message {
    public static final int STATUS_PENDING = 0;
    public static final int STATUS_SENT = 1;
    public static final int STATUS_DELIVERED = 2;
    public static final int STATUS_READ = 3;

    public static final int TYPE_CHAT = 0;
    public static final int TYPE_GROUP_INVITATION = 1;

    public final int id;
    public final String sender;
    public final String recipient;
    public final String plaintext;
    public final long timestamp;
    public final boolean isOutgoing;
    public final int status;
    public final int messageType;

    public Message(int id, String sender, String recipient, String plaintext,
                   long timestamp, boolean isOutgoing, int status, int messageType) {
        this.id = id;
        this.sender = sender;
        this.recipient = recipient;
        this.plaintext = plaintext;
        this.timestamp = timestamp;
        this.isOutgoing = isOutgoing;
        this.status = status;
        this.messageType = messageType;
    }

    public String getStatusString() {
        switch (status) {
            case STATUS_PENDING: return "pending";
            case STATUS_SENT: return "sent";
            case STATUS_DELIVERED: return "delivered";
            case STATUS_READ: return "read";
            default: return "unknown";
        }
    }
}
