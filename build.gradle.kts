plugins {
    kotlin("jvm") version "2.0.0"
    id("org.jetbrains.kotlin.plugin.serialization") version "2.0.20-RC2"
}

group = "perun_network.ecdsa_threshold"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
    maven("https://jitpack.io")
}

dependencies {
// define the BOM and its version
    implementation(platform("org.kotlincrypto.hash:bom:0.5.3"))
    testImplementation(kotlin("test"))
    implementation(kotlin("stdlib"))
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-cbor:1.7.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0-RC")
    implementation("com.appmattus.crypto:cryptohash:1.0.2")
    implementation("org.jetbrains.kotlin:kotlin-reflect:1.5.0")
    implementation("fr.acinq.secp256k1:secp256k1-kmp:0.15.0")
    implementation("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm:0.15.0")
    implementation("org.kotlincrypto.hash:sha2")
    implementation("com.ionspin.kotlin:bignum:0.3.8")
}

tasks.test {
    useJUnitPlatform()
}
kotlin {
    jvmToolchain(11)
}