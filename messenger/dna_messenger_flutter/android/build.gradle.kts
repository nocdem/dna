allprojects {
    repositories {
        google()
        mavenCentral()
        maven { url = uri("https://jitpack.io") }
    }
}

val newBuildDir: Directory =
    rootProject.layout.buildDirectory
        .dir("../../build")
        .get()
rootProject.layout.buildDirectory.value(newBuildDir)

subprojects {
    val newSubprojectBuildDir: Directory = newBuildDir.dir(project.name)
    project.layout.buildDirectory.value(newSubprojectBuildDir)
}
subprojects {
    project.evaluationDependsOn(":app")
}

// Force consistent JVM 17 + inject namespace for all library subprojects.
// Skip :app (already evaluated via evaluationDependsOn) to avoid
// "Cannot run afterEvaluate when project is already evaluated" error.
subprojects {
    if (name != "app") {
        afterEvaluate {
            // Force JVM target 17 (overrides plugin defaults like 1.8)
            if (extensions.findByName("android") != null) {
                val android = extensions.getByName("android")
                if (android is com.android.build.gradle.LibraryExtension) {
                    android.compileOptions {
                        sourceCompatibility = JavaVersion.VERSION_17
                        targetCompatibility = JavaVersion.VERSION_17
                    }
                    // Inject namespace from manifest if missing
                    if (android.namespace.isNullOrEmpty()) {
                        val manifest = file("src/main/AndroidManifest.xml")
                        if (manifest.exists()) {
                            val pkg = Regex("""package\s*=\s*"([^"]+)"""")
                                .find(manifest.readText())?.groupValues?.get(1)
                            if (pkg != null) {
                                android.namespace = pkg
                            }
                        }
                    }
                }
            }
            // Kotlin JVM target 17
            tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
                compilerOptions {
                    jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
                }
            }
        }
    }
}

tasks.register<Delete>("clean") {
    delete(rootProject.layout.buildDirectory)
}
