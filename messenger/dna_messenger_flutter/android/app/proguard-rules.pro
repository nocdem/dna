# ProGuard/R8 rules for DNA Messenger

# Keep DNA Messenger JNI classes (called from native code)
-keep class io.cpunk.dna_messenger.DnaNotificationHelper {
    public void onOutboxUpdated(java.lang.String, java.lang.String);
}
-keep class io.cpunk.dna_messenger.DnaMessengerService { *; }
