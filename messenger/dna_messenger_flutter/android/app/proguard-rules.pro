# ProGuard/R8 rules for DNA Messenger
# Service and notification helper rules removed in v0.9.7

# Keep DnaKeyStore for JNI access from native code (TEE key wrapping)
# This class is only called via JNI FindClass — R8 would strip it without this rule
-keep class io.cpunk.dna_connect.DnaKeyStore { *; }
