# DNA Messenger SDK - ProGuard Rules

# Keep all JNI methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep SDK public API
-keep class io.cpunk.dna.DNAEngine { *; }
-keep class io.cpunk.dna.Contact { *; }
-keep class io.cpunk.dna.Message { *; }
-keep class io.cpunk.dna.Group { *; }
-keep class io.cpunk.dna.Invitation { *; }
-keep class io.cpunk.dna.Wallet { *; }
-keep class io.cpunk.dna.Balance { *; }
-keep class io.cpunk.dna.Transaction { *; }
-keep class io.cpunk.dna.DNAEvent { *; }

# Keep callback interfaces
-keep interface io.cpunk.dna.DNAEngine$* { *; }
