# ProGuard/R8 rules for DNA Messenger

# Keep Gson TypeToken generic signatures (flutter_local_notifications uses Gson)
# Without this, R8 strips generic info causing "TypeToken must be created with a type argument" crash
-keep class com.google.gson.reflect.TypeToken { *; }
-keep class * extends com.google.gson.reflect.TypeToken

# Keep Gson annotations
-keepattributes Signature
-keepattributes *Annotation*

# Keep flutter_local_notifications classes
-keep class com.dexterous.** { *; }

# Keep DNA Messenger JNI classes (called from native code)
-keep class io.cpunk.dna_messenger.DnaNotificationHelper {
    public void onOutboxUpdated(java.lang.String, java.lang.String);
}
-keep class io.cpunk.dna_messenger.DnaMessengerService { *; }
