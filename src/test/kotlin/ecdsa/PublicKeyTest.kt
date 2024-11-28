package ecdsa

import org.junit.jupiter.api.Assertions.assertEquals
import perun_network.ecdsa_threshold.ecdsa.PublicKey
import perun_network.ecdsa_threshold.math.sampleScalar
import kotlin.test.Test
import kotlin.test.assertFails

class PublicKeyTest {
    @Test
    fun testPublicKey() {
        val x = sampleScalar()
        val X = x.actOnBase()
        val validBytes = X.toPublicKey().value
        val publicKey = PublicKey.newPublicKey(validBytes)
        assertEquals(X.toPublicKey(), publicKey)
    }

    @Test
    fun testPublicKeyFails() {
        val x = sampleScalar()
        val X = x.actOnBase()
        assertFails {
            PublicKey.newPublicKey(X.toByteArray())
        }
    }

}