plugins {
    kotlin("jvm") version "2.0.0"
    id("org.jetbrains.kotlin.plugin.serialization") version "2.0.20-RC2"
    id("jacoco")
    id("maven-publish")
}

group = "perun_network.ecdsa_threshold"
version = "0.1.2"

repositories {
    mavenCentral()
    maven("https://jitpack.io")
}


dependencies {
    // define the BOM and its version
    implementation(platform("org.kotlincrypto.hash:bom:0.5.3"))
    implementation("org.kotlincrypto.hash:sha2")
    testImplementation(kotlin("test"))
    implementation(kotlin("stdlib"))
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-cbor:1.7.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0-RC")
    implementation("com.appmattus.crypto:cryptohash:1.0.2")
    implementation("org.jetbrains.kotlin:kotlin-reflect:1.5.0")
    implementation("fr.acinq.secp256k1:secp256k1-kmp:0.15.0")
    implementation("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm:0.15.0")

    implementation("com.ionspin.kotlin:bignum:0.3.8")
    // Add Kotlin Logging
    implementation("io.github.microutils:kotlin-logging:3.0.5")
    implementation("ch.qos.logback:logback-classic:1.4.12")

}

tasks.test {
    useJUnitPlatform()
}
kotlin {
    jvmToolchain(11)
}


jacoco {
    toolVersion = "0.8.10" // Adjust to the latest JaCoCo version
}

tasks.jacocoTestReport {
    reports {
        csv.required.set(true)
        xml.required.set(true) // Generate XML report
        html.required.set(true) // Generate HTML report
    }
    classDirectories.setFrom(files(classDirectories.files.map {
        fileTree(it) {
            setExcludes(listOf(
                "**/MainKt.class",
                "perun_network/ecdsa_threshold/tuple/*",
            ))
        }
    }))
}

publishing {
    publications {
        create<MavenPublication>("release") {
            from(components["java"])
            groupId = "com.github.perun-network"
            artifactId = "atala-prism-threshold"
            version = "0.1.3"
        }
    }
}

