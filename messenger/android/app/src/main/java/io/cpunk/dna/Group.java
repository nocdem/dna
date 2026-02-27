package io.cpunk.dna;

public class Group {
    public final String uuid;
    public final String name;
    public final String creator;
    public final int memberCount;
    public final long createdAt;

    public Group(String uuid, String name, String creator, int memberCount, long createdAt) {
        this.uuid = uuid;
        this.name = name;
        this.creator = creator;
        this.memberCount = memberCount;
        this.createdAt = createdAt;
    }
}
