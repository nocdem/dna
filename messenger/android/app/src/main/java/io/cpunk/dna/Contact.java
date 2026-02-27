package io.cpunk.dna;

public class Contact {
    public final String fingerprint;
    public final String displayName;
    public final boolean isOnline;
    public final long lastSeen;

    public Contact(String fingerprint, String displayName, boolean isOnline, long lastSeen) {
        this.fingerprint = fingerprint;
        this.displayName = displayName;
        this.isOnline = isOnline;
        this.lastSeen = lastSeen;
    }

    public String getShortFingerprint() {
        if (fingerprint != null && fingerprint.length() >= 16) {
            return fingerprint.substring(0, 8) + "..." + fingerprint.substring(fingerprint.length() - 8);
        }
        return fingerprint;
    }
}
