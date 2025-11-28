package io.cpunk.dna;

public class Transaction {
    public final String txHash;
    public final String direction;
    public final String amount;
    public final String token;
    public final String otherAddress;
    public final String timestamp;
    public final String status;

    public Transaction(String txHash, String direction, String amount, String token,
                       String otherAddress, String timestamp, String status) {
        this.txHash = txHash;
        this.direction = direction;
        this.amount = amount;
        this.token = token;
        this.otherAddress = otherAddress;
        this.timestamp = timestamp;
        this.status = status;
    }

    public boolean isSent() {
        return "sent".equalsIgnoreCase(direction);
    }

    public boolean isReceived() {
        return "received".equalsIgnoreCase(direction);
    }
}
