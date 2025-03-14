package ecdsa

import perun_network.ecdsa_threshold.ecdsa.Signature
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.util.*

class SignatureTest {

    @Test
    fun `test encode and decode signature`() {
        // Create random signature bytes
        val r = ByteArray(32) { it.toByte() }
        val s = ByteArray(32) { (it + 1).toByte() }
        val signature = Signature(r, s)

        // Encode to secp256k1 signature format
        val encoded = signature.toSecp256k1Signature()
        assertEquals(64, encoded.size)

        // Decode back into a signature object
        val decoded = Signature.fromSecp256k1Signature(encoded)

        // Verify the original and decoded signatures match
        assertEquals(signature, decoded)
    }

    @Test
    fun `test equals and hashCode`() {
        val r1 = ByteArray(32) { it.toByte() }
        val s1 = ByteArray(32) { (it + 1).toByte() }
        val signature1 = Signature(r1, s1)

        val r2 = ByteArray(32) { it.toByte() }
        val s2 = ByteArray(32) { (it + 1).toByte() }
        val signature2 = Signature(r2, s2)

        assertEquals(signature1, signature2)
        assertEquals(signature1.hashCode(), signature2.hashCode())

        val differentR = ByteArray(32) { (it + 2).toByte() }
        val differentSignature = Signature(differentR, s1)

        assertNotEquals(signature1, differentSignature)
        assertNotEquals(signature1.hashCode(), differentSignature.hashCode())
    }
}
