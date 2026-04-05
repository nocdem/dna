import java.util.Properties
import java.io.FileInputStream

plugins {
    id("com.android.application")
    id("kotlin-android")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

// Load release keystore properties (not committed to git)
val keystorePropertiesFile = file(System.getProperty("user.home") + "/keys/keystore.properties")
val keystoreProperties = Properties()
if (keystorePropertiesFile.exists()) {
    keystoreProperties.load(FileInputStream(keystorePropertiesFile))
}

android {
    namespace = "io.cpunk.dna_connect"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = flutter.ndkVersion

    compileOptions {
        // Enable core library desugaring for Java 8+ APIs on older Android
        isCoreLibraryDesugaringEnabled = true
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = JavaVersion.VERSION_17.toString()
    }

    signingConfigs {
        create("shared") {
            storeFile = file("debug.keystore")
            storePassword = "android"
            keyAlias = "androiddebugkey"
            keyPassword = "android"
        }
        if (keystorePropertiesFile.exists()) {
            create("release") {
                storeFile = file(keystoreProperties.getProperty("storeFile", ""))
                storePassword = keystoreProperties.getProperty("storePassword", "")
                keyAlias = keystoreProperties.getProperty("keyAlias", "")
                keyPassword = keystoreProperties.getProperty("keyPassword", "")
            }
        }
    }

    defaultConfig {
        applicationId = "io.cpunk.dna_connect"
        minSdk = flutter.minSdkVersion
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName

    }

    // ABI restriction note:
    //
    // libdna.so (our C backend) is only cross-compiled for arm64-v8a
    // (see CI build:native-android-arm64 job). We must restrict the
    // final APK/AAB to arm64-v8a only so that armeabi-v7a or x86_64
    // devices don't install an APK that would crash at runtime with
    // UnsatisfiedLinkError (libdna.so missing for their architecture).
    //
    // Flutter's gradle plugin forces its own ndk.abiFilters
    // (armeabi-v7a,arm64-v8a,x86_64) and rejects splits.abi configs
    // here — so we can NOT restrict ABIs in this gradle file.
    //
    // Instead, ABI restriction MUST be passed via CLI:
    //   flutter build apk       --release --target-platform=android-arm64
    //   flutter build appbundle --release --target-platform=android-arm64
    //
    // CI and any release build scripts must include this flag.

    buildTypes {
        debug {
            signingConfig = signingConfigs.getByName("shared")
        }
        release {
            signingConfig = if (keystorePropertiesFile.exists())
                signingConfigs.getByName("release")
            else
                signingConfigs.getByName("shared")  // CI fallback: debug keystore
            // Enable R8 minification with ProGuard rules
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
}

flutter {
    source = "../.."
}

dependencies {
    // Core library desugaring for Java 8+ APIs on older Android
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.4")
}
