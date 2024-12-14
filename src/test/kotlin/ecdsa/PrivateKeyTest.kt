package ecdsa

import fr.acinq.secp256k1.Secp256k1
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Test
import org.kotlincrypto.hash.sha2.SHA256
import perun_network.ecdsa_threshold.ecdsa.PrivateKey.Companion.newPrivateKey
import perun_network.ecdsa_threshold.math.sampleScalar
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class PrivateKeyTest {
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

    @Test
    fun testPrivateKeyAdd() {
        val x = sampleScalar()
        val xPriv = newPrivateKey(x.toByteArray())
        val y = sampleScalar()
        val yPriv = newPrivateKey(y.toByteArray())

        val z = x.add(y)
        val zPriv = newPrivateKey(z.toByteArray())
        val zPriv2 = xPriv.add(yPriv)

        assertEquals(zPriv, zPriv2)
    }

    @Test
    fun testPrivateKeyNeg() {
        val x = sampleScalar()
        val xPriv = newPrivateKey(x.toByteArray())

        // Perform negation
        val negatedKey = xPriv.neg()

        // Check that the negated key is not null and valid
        assertNotNull(negatedKey, "Negated key should not be null")
        assert(Secp256k1.secKeyVerify(negatedKey.toByteArray())) { "Negated key must be valid" }

        // Apply negation twice and check if it equals the original key
        val doubleNegatedKey = negatedKey.neg()
        assertEquals(xPriv, doubleNegatedKey, "Double negation should yield the original key")
    }

    @Test
    fun testPrivateKeyMul() {
        val x = sampleScalar()
        val xPriv = newPrivateKey(x.toByteArray())
        val y = sampleScalar()
        val yPriv = newPrivateKey(y.toByteArray())

        val z = x.multiply(y)
        val zPriv = newPrivateKey(z.toByteArray())
        val zPriv2 = xPriv.mul(yPriv)

        assertEquals(zPriv, zPriv2)
    }

    @Test
    fun testPrivateKeyFails() {
        val invalidSizeData = ByteArray(16) // Less than 32 bytes
        assertFailsWith<IllegalArgumentException>("data must be 32 bytes") {
            newPrivateKey(invalidSizeData)
        }

        val oversizedData = ByteArray(33) // More than 32 bytes
        assertFailsWith<IllegalArgumentException>("data must be 32 bytes") {
            newPrivateKey(oversizedData)
        }

        val invalidKeyData = ByteArray(32) { 0 } // Invalid private key data
        assertFailsWith<IllegalArgumentException>("invalid private key") {
            newPrivateKey(invalidKeyData)
        }
    }
}