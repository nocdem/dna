package io.cpunk.dna;

public class Wallet {
    public static final int SIG_DILITHIUM = 0;
    public static final int SIG_PICNIC = 1;
    public static final int SIG_BLISS = 2;
    public static final int SIG_TESLA = 3;

    public final String name;
    public final String address;
    public final int sigType;
    public final boolean isProtected;

    public Wallet(String name, String address, int sigType, boolean isProtected) {
        this.name = name;
        this.address = address;
        this.sigType = sigType;
        this.isProtected = isProtected;
    }

    public String getSigTypeString() {
        switch (sigType) {
            case SIG_DILITHIUM: return "Dilithium";
            case SIG_PICNIC: return "Picnic";
            case SIG_BLISS: return "BLISS";
            case SIG_TESLA: return "TESLA";
            default: return "Unknown";
        }
    }
}
