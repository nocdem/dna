/*
 * DNA Messenger Engine - Android SDK
 *
 * Post-quantum encrypted messenger with Cellframe wallet integration.
 * Uses Kyber1024 (ML-KEM-1024) for key exchange and Dilithium5 (ML-DSA-87) for signatures.
 *
 * Usage:
 *   DNAEngine engine = DNAEngine.getInstance();
 *   engine.initialize(context, dataDir);
 *   engine.setEventListener(listener);
 *   engine.loadIdentity(fingerprint, callback);
 */

package io.cpunk.dna;

import android.content.Context;
import java.io.File;

public class DNAEngine {
    private static DNAEngine instance;
    private boolean initialized = false;

    static {
        System.loadLibrary("dna_jni");
    }

    private DNAEngine() {}

    public static synchronized DNAEngine getInstance() {
        if (instance == null) {
            instance = new DNAEngine();
        }
        return instance;
    }

    /**
     * Initialize the DNA engine
     * @param context Android context
     * @param dataDir Data directory (null for default)
     * @return true on success
     */
    public boolean initialize(Context context, String dataDir) {
        if (initialized) return true;

        String dir = dataDir;
        if (dir == null) {
            dir = new File(context.getFilesDir(), "dna").getAbsolutePath();
        }

        // Ensure directory exists
        new File(dir).mkdirs();

        initialized = nativeCreate(dir);
        return initialized;
    }

    /**
     * Shutdown the engine
     */
    public void shutdown() {
        if (initialized) {
            nativeDestroy();
            initialized = false;
        }
    }

    /**
     * Check if engine is initialized
     */
    public boolean isInitialized() {
        return initialized;
    }

    /**
     * Set event listener for pushed events
     */
    public void setEventListener(EventListener listener) {
        nativeSetEventListener(listener);
    }

    /**
     * Get current identity fingerprint
     * @return 128-char hex fingerprint or null
     */
    public String getFingerprint() {
        return nativeGetFingerprint();
    }

    // ========== IDENTITY ==========
    // v0.3.0: listIdentities() removed - single-user model, use hasIdentity() instead

    /**
     * Create new identity from BIP39 seeds
     */
    public long createIdentity(byte[] signingSeed, byte[] encryptionSeed, IdentityCreatedCallback callback) {
        return nativeCreateIdentity(signingSeed, encryptionSeed, callback);
    }

    /**
     * Load and activate identity
     */
    public long loadIdentity(String fingerprint, CompletionCallback callback) {
        return nativeLoadIdentity(fingerprint, callback);
    }

    /**
     * Register human-readable name
     */
    public long registerName(String name, CompletionCallback callback) {
        return nativeRegisterName(name, callback);
    }

    /**
     * Get display name for fingerprint
     */
    public long getDisplayName(String fingerprint, DisplayNameCallback callback) {
        return nativeGetDisplayName(fingerprint, callback);
    }

    // ========== CONTACTS ==========

    /**
     * Get contact list
     */
    public long getContacts(ContactsCallback callback) {
        return nativeGetContacts(callback);
    }

    /**
     * Add contact by fingerprint or name
     */
    public long addContact(String identifier, CompletionCallback callback) {
        return nativeAddContact(identifier, callback);
    }

    /**
     * Remove contact
     */
    public long removeContact(String fingerprint, CompletionCallback callback) {
        return nativeRemoveContact(fingerprint, callback);
    }

    // ========== MESSAGING ==========

    /**
     * Send message to contact
     */
    public long sendMessage(String recipientFingerprint, String message, CompletionCallback callback) {
        return nativeSendMessage(recipientFingerprint, message, callback);
    }

    /**
     * Get conversation with contact
     */
    public long getConversation(String contactFingerprint, MessagesCallback callback) {
        return nativeGetConversation(contactFingerprint, callback);
    }

    // ========== GROUPS ==========

    /**
     * Get groups
     */
    public long getGroups(GroupsCallback callback) {
        return nativeGetGroups(callback);
    }

    /**
     * Create new group
     */
    public long createGroup(String name, String[] memberFingerprints, GroupCreatedCallback callback) {
        return nativeCreateGroup(name, memberFingerprints, callback);
    }

    /**
     * Send group message
     */
    public long sendGroupMessage(String groupUuid, String message, CompletionCallback callback) {
        return nativeSendGroupMessage(groupUuid, message, callback);
    }

    /**
     * Get pending invitations
     */
    public long getInvitations(InvitationsCallback callback) {
        return nativeGetInvitations(callback);
    }

    /**
     * Accept invitation
     */
    public long acceptInvitation(String groupUuid, CompletionCallback callback) {
        return nativeAcceptInvitation(groupUuid, callback);
    }

    /**
     * Reject invitation
     */
    public long rejectInvitation(String groupUuid, CompletionCallback callback) {
        return nativeRejectInvitation(groupUuid, callback);
    }

    // ========== WALLET ==========

    /**
     * List wallets
     */
    public long listWallets(WalletsCallback callback) {
        return nativeListWallets(callback);
    }

    /**
     * Get balances for wallet
     */
    public long getBalances(int walletIndex, BalancesCallback callback) {
        return nativeGetBalances(walletIndex, callback);
    }

    /**
     * Send tokens
     */
    public long sendTokens(int walletIndex, String recipient, String amount,
                          String token, String network, CompletionCallback callback) {
        return nativeSendTokens(walletIndex, recipient, amount, token, network, callback);
    }

    /**
     * Get transaction history
     */
    public long getTransactions(int walletIndex, String network, TransactionsCallback callback) {
        return nativeGetTransactions(walletIndex, network, callback);
    }

    // ========== P2P ==========

    /**
     * Check if peer is online
     */
    public boolean isPeerOnline(String fingerprint) {
        return nativeIsPeerOnline(fingerprint);
    }

    /**
     * Refresh presence in DHT
     */
    public long refreshPresence(CompletionCallback callback) {
        return nativeRefreshPresence(callback);
    }

    /**
     * Handle network connectivity change
     *
     * Call when network connectivity changes (WiFi to cellular, etc.).
     * Reinitializes the DHT connection with a fresh socket.
     *
     * @return 0 on success, -1 on error
     */
    public int networkChanged() {
        return nativeNetworkChanged();
    }

    // ========== CALLBACKS ==========

    public interface CompletionCallback {
        void onCompletion(long requestId, int error);
    }

    // v0.3.0: IdentitiesCallback removed - single-user model

    public interface IdentityCreatedCallback {
        void onIdentityCreated(long requestId, int error, String fingerprint);
    }

    public interface DisplayNameCallback {
        void onDisplayName(long requestId, int error, String displayName);
    }

    public interface ContactsCallback {
        void onContacts(long requestId, int error, Contact[] contacts);
    }

    public interface MessagesCallback {
        void onMessages(long requestId, int error, Message[] messages);
    }

    public interface GroupsCallback {
        void onGroups(long requestId, int error, Group[] groups);
    }

    public interface GroupCreatedCallback {
        void onGroupCreated(long requestId, int error, String groupUuid);
    }

    public interface InvitationsCallback {
        void onInvitations(long requestId, int error, Invitation[] invitations);
    }

    public interface WalletsCallback {
        void onWallets(long requestId, int error, Wallet[] wallets);
    }

    public interface BalancesCallback {
        void onBalances(long requestId, int error, Balance[] balances);
    }

    public interface TransactionsCallback {
        void onTransactions(long requestId, int error, Transaction[] transactions);
    }

    public interface EventListener {
        void onEvent(int eventType, String data1, String data2);
    }

    // ========== NATIVE METHODS ==========

    private native boolean nativeCreate(String dataDir);
    private native void nativeDestroy();
    private native void nativeSetEventListener(EventListener listener);
    private native String nativeGetFingerprint();

    // v0.3.0: nativeListIdentities removed - single-user model
    private native long nativeCreateIdentity(byte[] signingSeed, byte[] encryptionSeed, IdentityCreatedCallback callback);
    private native long nativeLoadIdentity(String fingerprint, CompletionCallback callback);
    private native long nativeRegisterName(String name, CompletionCallback callback);
    private native long nativeGetDisplayName(String fingerprint, DisplayNameCallback callback);

    private native long nativeGetContacts(ContactsCallback callback);
    private native long nativeAddContact(String identifier, CompletionCallback callback);
    private native long nativeRemoveContact(String fingerprint, CompletionCallback callback);

    private native long nativeSendMessage(String recipient, String message, CompletionCallback callback);
    private native long nativeGetConversation(String contact, MessagesCallback callback);

    private native long nativeGetGroups(GroupsCallback callback);
    private native long nativeCreateGroup(String name, String[] members, GroupCreatedCallback callback);
    private native long nativeSendGroupMessage(String groupUuid, String message, CompletionCallback callback);
    private native long nativeGetInvitations(InvitationsCallback callback);
    private native long nativeAcceptInvitation(String groupUuid, CompletionCallback callback);
    private native long nativeRejectInvitation(String groupUuid, CompletionCallback callback);

    private native long nativeListWallets(WalletsCallback callback);
    private native long nativeGetBalances(int walletIndex, BalancesCallback callback);
    private native long nativeSendTokens(int walletIndex, String recipient, String amount, String token, String network, CompletionCallback callback);
    private native long nativeGetTransactions(int walletIndex, String network, TransactionsCallback callback);

    private native boolean nativeIsPeerOnline(String fingerprint);
    private native long nativeRefreshPresence(CompletionCallback callback);
    private native int nativeNetworkChanged();
}
