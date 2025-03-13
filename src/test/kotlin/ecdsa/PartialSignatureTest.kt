package ecdsa

import org.junit.jupiter.api.Test
import org.kotlincrypto.hash.sha2.SHA256
import perun_network.ecdsa_threshold.ecdsa.PrivateKey.Companion.newPrivateKey
import perun_network.ecdsa_threshold.math.sampleScalar
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PartialSignatureTest {
    @Test
    fun testPrivateKey() {
        val x = sampleScalar()
        val X = x.actOnBase()
        val xBytes = x.toByteArray()

        val privateKey = newPrivateKey(xBytes)
        val message = "Hello, Bitcoin!".toByteArray()
        val hash = SHA256().digest(message)
        val sig = privateKey.sign(hash)
        assertTrue(sig.verifyWithPoint(hash , X))

        val xScalar = privateKey.toScalar()
        assertEquals(x, xScalar)
    }
}