package io.cpunk.dna;

/**
 * Event types pushed by the DNA engine
 */
public class DNAEvent {
    public static final int DHT_CONNECTED = 0;
    public static final int DHT_DISCONNECTED = 1;
    public static final int MESSAGE_RECEIVED = 2;
    public static final int MESSAGE_SENT = 3;
    public static final int MESSAGE_DELIVERED = 4;
    public static final int MESSAGE_READ = 5;
    public static final int CONTACT_ONLINE = 6;
    public static final int CONTACT_OFFLINE = 7;
    public static final int GROUP_INVITATION_RECEIVED = 8;
    public static final int GROUP_MEMBER_JOINED = 9;
    public static final int GROUP_MEMBER_LEFT = 10;
    public static final int IDENTITY_LOADED = 11;
    public static final int ERROR = 12;

    public static String getEventName(int eventType) {
        switch (eventType) {
            case DHT_CONNECTED: return "DHT_CONNECTED";
            case DHT_DISCONNECTED: return "DHT_DISCONNECTED";
            case MESSAGE_RECEIVED: return "MESSAGE_RECEIVED";
            case MESSAGE_SENT: return "MESSAGE_SENT";
            case MESSAGE_DELIVERED: return "MESSAGE_DELIVERED";
            case MESSAGE_READ: return "MESSAGE_READ";
            case CONTACT_ONLINE: return "CONTACT_ONLINE";
            case CONTACT_OFFLINE: return "CONTACT_OFFLINE";
            case GROUP_INVITATION_RECEIVED: return "GROUP_INVITATION_RECEIVED";
            case GROUP_MEMBER_JOINED: return "GROUP_MEMBER_JOINED";
            case GROUP_MEMBER_LEFT: return "GROUP_MEMBER_LEFT";
            case IDENTITY_LOADED: return "IDENTITY_LOADED";
            case ERROR: return "ERROR";
            default: return "UNKNOWN(" + eventType + ")";
        }
    }
}
