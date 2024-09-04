package perun_network.ecdsa_threshold.protocols.cmp.paillier

import kotlinx.serialization.Serializable
import perun_network.ecdsa_threshold.hash.WriterToWithDomain
import perun_network.ecdsa_threshold.math.sample.SecureRandomInputStream
import perun_network.ecdsa_threshold.math.sample.unitModN
import perun_network.ecdsa_threshold.params.BytesCiphertext
import perun_network.ecdsa_threshold.serializers.BigIntegerSerializer
import java.io.OutputStream
import java.math.BigInteger
import java.security.SecureRandom

@Serializable()
class CipherText (
    @Serializable(with = BigIntegerSerializer::class)
    var c: BigInteger
) : WriterToWithDomain {
    override fun writeTo(outputStream: OutputStream): Long {
        val buf = ByteArray(BytesCiphertext)
        c.toByteArray().copyInto(buf)
        outputStream.write(buf)
        return buf.size.toLong()
    }

    override fun domain(): String {
        return "Paillier Ciphertext"
    }

    // Add sets ct to the homomorphic sum ct ⊕ ct₂.
    // ct ← ct•ct₂ (mod N²).
    fun add(pk: PublicKey, ct2: CipherText?): CipherText {
        ct2?.let {
            val squaredN = pk.modulusSquared()
            c = c.mod(squaredN).multiply(ct2.c.mod(squaredN)).mod(squaredN)
        }
        return this
    }

    // Mul sets ct to the homomorphic multiplication of k ⊙ ct.
    // ct ← ctᵏ (mod N²).
    fun mul(pk: PublicKey, k: BigInteger?): CipherText {
        k?.let {
            val squaredN = pk.modulusSquared()
            c = c.modPow(k, squaredN)
        }
        return this
    }

    override fun equals(other: Any?): Boolean {
        return (other is CipherText && c == other.c)
    }

    fun clone(): CipherText {
        return CipherText(c)
    }

    // Randomize multiplies the ciphertext's nonce by a newly generated one.
    // ct ← ct ⋅ nonceᴺ (mod N²).
    // If nonce is nil, a random one is generated.
    // The receiver is updated, and the nonce update is returned.
    fun randomize(pk: PublicKey, nonce: BigInteger?): BigInteger {
        val squaredN = pk.modulusSquared()
        val finalNonce = nonce ?: unitModN(SecureRandomInputStream(SecureRandom()), pk.modulus())

        // c = c * r ^ N
        val tmp = finalNonce.modPow(pk.modulus(), squaredN)
        c = c.mod(squaredN).multiply(tmp).mod(squaredN)
        return finalNonce
    }

    fun value() : BigInteger = c
}