package io.cpunk.dna;

public class Balance {
    public final String token;
    public final String balance;
    public final String network;

    public Balance(String token, String balance, String network) {
        this.token = token;
        this.balance = balance;
        this.network = network;
    }
}
