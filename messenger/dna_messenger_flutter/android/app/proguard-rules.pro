# ProGuard/R8 rules for DNA Connect
#
# Keep rules for release build with R8 minification enabled.
# Flutter Gradle plugin auto-includes Flutter embedding keep rules,
# and each plugin bundles its own consumer-rules.pro — so we only
# need app-specific rules + generic safety nets here.
#
# If release APK crashes on launch with ClassNotFoundException or
# NoSuchMethodException after R8 minification, add a keep rule here.

# ── App-specific JNI bridge (TEE key wrapping) ────────────────────
# DnaKeyStore is called via JNI GetStaticMethodID from
# shared/crypto/utils/platform_keystore_android.c
# R8 would strip it since there's no static reference from Kotlin/Java.
-keep class io.cpunk.dna_connect.DnaKeyStore { *; }
-keep class io.cpunk.dna_connect.DnaKeyStore$Companion { *; }

# ── Generic native method safety ───────────────────────────────────
# Any method marked `native` is called from C — keep signatures intact.
-keepclasseswithmembernames class * {
    native <methods>;
}

# ── Retained attributes for reflection, generics, annotations ─────
-keepattributes *Annotation*
-keepattributes Signature
-keepattributes InnerClasses,EnclosingMethod
-keepattributes Exceptions
-keepattributes SourceFile,LineNumberTable

# Hide source file name in stack traces (shown as "SourceFile")
-renamesourcefileattribute SourceFile

# ── Kotlin metadata ────────────────────────────────────────────────
# Keep Kotlin reflection metadata (required for some libraries).
-keep class kotlin.Metadata { *; }
-keepclassmembers class **$WhenMappings { <fields>; }
-keepclassmembers class kotlin.Metadata {
    public <methods>;
}

# ── Enums (common source of obfuscation bugs) ─────────────────────
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# ── Parcelable (Android IPC) ──────────────────────────────────────
-keepclassmembers class * implements android.os.Parcelable {
    public static final ** CREATOR;
}

# ── Serializable (defensive) ──────────────────────────────────────
-keepclassmembers class * implements java.io.Serializable {
    static final long serialVersionUID;
    private static final java.io.ObjectStreamField[] serialPersistentFields;
    !static !transient <fields>;
    private void writeObject(java.io.ObjectOutputStream);
    private void readObject(java.io.ObjectInputStream);
    java.lang.Object writeReplace();
    java.lang.Object readResolve();
}

# ── R class fields (resource IDs accessed by reflection) ──────────
-keepclassmembers class **.R$* {
    public static <fields>;
}

# ── Flutter engine (belt-and-suspenders — Flutter normally handles this) ──
-keep class io.flutter.embedding.** { *; }
-keep class io.flutter.plugin.common.** { *; }
-dontwarn io.flutter.embedding.**

# ── Plugins with known R8 gotchas ─────────────────────────────────

# mobile_scanner (ML Kit) — reflection on barcode format enums
-keep class com.google.mlkit.** { *; }
-dontwarn com.google.mlkit.**

# flutter_local_notifications — BroadcastReceiver subclasses, Gson types
-keep class com.dexterous.** { *; }
-keep class com.dexterous.flutterlocalnotifications.models.** { *; }
-keep class * extends com.google.gson.TypeAdapter
-keep class * implements com.google.gson.TypeAdapterFactory
-keep class * implements com.google.gson.JsonSerializer
-keep class * implements com.google.gson.JsonDeserializer
-keepclassmembers,allowobfuscation class * {
    @com.google.gson.annotations.SerializedName <fields>;
}

# video_player / just_audio — ExoPlayer via reflection
-keep class com.google.android.exoplayer2.** { *; }
-dontwarn com.google.android.exoplayer2.**

# flutter_secure_storage — uses Android Keystore via reflection
-keep class androidx.security.** { *; }
-keep class com.it_nomads.fluttersecurestorage.** { *; }
-dontwarn com.it_nomads.fluttersecurestorage.**

# local_auth — BiometricPrompt on older Android versions
-keep class androidx.biometric.** { *; }

# record — audio recorder
-keep class com.llfbandit.record.** { *; }

# light_compressor — video compression via native libs
-keep class com.linkedin.android.litr.** { *; }
-dontwarn com.linkedin.android.litr.**

# share_plus, url_launcher, permission_handler — commonly fine with defaults

# ── Kotlin coroutines (used by plugins) ────────────────────────────
-keepclassmembers class kotlinx.coroutines.** {
    volatile <fields>;
}
-dontwarn kotlinx.coroutines.**

# ── androidx.lifecycle (used widely) ───────────────────────────────
-keep class androidx.lifecycle.DefaultLifecycleObserver
-keep class * extends androidx.lifecycle.ViewModel { <init>(...); }
