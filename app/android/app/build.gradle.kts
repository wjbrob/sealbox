import java.io.FileInputStream
import java.util.Properties

plugins {
    id("com.android.application")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

// Release signing (docs/RELEASE.md, testing/keys/README.md). The properties file is looked up as
//   1. $SEALBOX_KEY_PROPERTIES  — a path; scripts/gate_release.sh and CI point it at a keystore
//   2. android/key.properties   — git-ignored; copy android/key.properties.example for the TEST key
// Without either, release builds fall back to the debug key (installable, never shippable).
// Debug builds (gate G10, the emulator loop) never read any of this.
val keyPropertiesFile: File =
    System.getenv("SEALBOX_KEY_PROPERTIES")?.takeIf { it.isNotBlank() }?.let { file(it) }
        ?: rootProject.file("key.properties")
val keyProperties = Properties().apply {
    if (keyPropertiesFile.isFile) FileInputStream(keyPropertiesFile).use { load(it) }
}
val hasReleaseKeystore = keyPropertiesFile.isFile && keyProperties.getProperty("storeFile") != null
if (hasReleaseKeystore) {
    logger.lifecycle("sealbox: release builds signed with ${keyProperties.getProperty("storeFile")} (from $keyPropertiesFile)")
} else {
    logger.lifecycle("sealbox: no key.properties — release builds use the debug signing key")
}

android {
    namespace = "dev.sealbox.sealbox_app"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = flutter.ndkVersion

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    defaultConfig {
        // Permanent once published to a store — decide the final id before the first upload.
        applicationId = "dev.sealbox.sealbox_app"
        minSdk = flutter.minSdkVersion
        targetSdk = flutter.targetSdkVersion
        // versionCode / versionName come from app/pubspec.yaml (`version: X.Y.Z+BUILD`), which
        // scripts/version.sh derives from the repository's single VERSION file.
        versionCode = flutter.versionCode
        versionName = flutter.versionName
    }

    signingConfigs {
        if (hasReleaseKeystore) {
            create("release") {
                // Relative paths resolve against android/app (Flutter convention).
                storeFile = file(keyProperties.getProperty("storeFile"))
                storePassword = keyProperties.getProperty("storePassword")
                keyAlias = keyProperties.getProperty("keyAlias")
                keyPassword = keyProperties.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            signingConfig =
                if (hasReleaseKeystore) signingConfigs.getByName("release")
                else signingConfigs.getByName("debug")
        }
    }
}

// Release builds must not reference dev-dependency plugins. Flutter's Gradle plugin already excludes
// their modules from release variants, but the shared, generated
// src/main/java/io/flutter/plugins/GeneratedPluginRegistrant.java can still register them:
// `flutter build --release --no-pub` skips its regeneration, and in a multi-agent checkout a concurrent
// `flutter test` / debug build rewrites it (with integration_test) seconds before javac runs — which
// fails with "package dev.flutter.plugins.integration_test does not exist". So, for release variants
// only, strip the registrations of plugins flagged dev_dependency in .flutter-plugins-dependencies
// right before the Java compile. Debug variants are untouched (the smoke test needs the plugin).
fun devDependencyPlugins(): Set<String> {
    val f = rootProject.file("../.flutter-plugins-dependencies")
    if (!f.isFile) return emptySet()
    val json = groovy.json.JsonSlurper().parse(f) as? Map<*, *> ?: return emptySet()
    val android = (json["plugins"] as? Map<*, *>)?.get("android") as? List<*> ?: return emptySet()
    return android.filterIsInstance<Map<*, *>>()
        .filter { it["dev_dependency"] == true }
        .mapNotNull { it["name"] as? String }
        .toSet()
}

fun stripDevPluginsFromRegistrant() {
    val registrant = file("src/main/java/io/flutter/plugins/GeneratedPluginRegistrant.java")
    val dev = devDependencyPlugins()
    if (!registrant.isFile || dev.isEmpty()) return
    val block = Regex(
        """\s*try \{\s*flutterEngine\.getPlugins\(\)\.add\(new [\w.]+\(\)\);\s*\} catch \(Exception e\) \{\s*Log\.e\(TAG, "Error registering plugin ([\w-]+), [^"]*", e\);\s*\}"""
    )
    val original = registrant.readText()
    val stripped = block.replace(original) { m -> if (m.groupValues[1] in dev) "" else m.value }
    if (stripped != original) {
        registrant.writeText(stripped)
        logger.lifecycle("sealbox: release compile — removed dev-dependency plugin registrations: " +
            dev.filter { original.contains("Error registering plugin $it,") }.joinToString(", "))
    }
}

tasks.configureEach {
    if (name.matches(Regex("(javaPreCompile|compile)\\w*Release(JavaWithJavac)?")) &&
        (name.startsWith("javaPreCompile") || name.endsWith("JavaWithJavac"))) {
        doFirst { stripDevPluginsFromRegistrant() }
    }
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}

flutter {
    source = "../.."
}
