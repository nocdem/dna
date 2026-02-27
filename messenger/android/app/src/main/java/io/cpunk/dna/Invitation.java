package io.cpunk.dna;

public class Invitation {
    public final String groupUuid;
    public final String groupName;
    public final String inviter;
    public final int memberCount;
    public final long invitedAt;

    public Invitation(String groupUuid, String groupName, String inviter,
                      int memberCount, long invitedAt) {
        this.groupUuid = groupUuid;
        this.groupName = groupName;
        this.inviter = inviter;
        this.memberCount = memberCount;
        this.invitedAt = invitedAt;
    }
}
