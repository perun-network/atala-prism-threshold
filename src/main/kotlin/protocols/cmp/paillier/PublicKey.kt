package perun_network.ecdsa_threshold.protocols.cmp.paillier

import kotlinx.serialization.Serializable
import perun_network.ecdsa_threshold.hash.WriterToWithDomain
import perun_network.ecdsa_threshold.math.sample.SecureRandomInputStream
import perun_network.ecdsa_threshold.math.sample.unitModN
import perun_network.ecdsa_threshold.params.BitsPaillier
import perun_network.ecdsa_threshold.serializers.BigIntegerSerializer
import java.io.OutputStream
import java.math.BigInteger
import java.security.SecureRandom

sealed class PaillierError(override val message: String) : Exception(message) {
    object PaillierLength: PaillierError("Wrong number bit length of Paillier modulus N")
    object PaillierEven: PaillierError("Modulus N is even")
    object PaillierNull: PaillierError("Modulus N is null")

}

@Serializable
data class PublicKey(
    @Serializable(with = BigIntegerSerializer::class)
    private val n: BigInteger,
    @Serializable(with = BigIntegerSerializer::class)
    private val nSquared: BigInteger,
    @Serializable(with = BigIntegerSerializer::class)
    private val nPlusOne: BigInteger,
) : WriterToWithDomain {
    companion object {
        // NewPublicKey returns an initialized paillier.PublicKey and caches N, N² and (N+1)
        fun newPublicKey(n: BigInteger): PublicKey {
            val nSquared = n.pow(2)
            val nPlusOne = n.add(BigInteger.ONE)

            return PublicKey(
                n = n,
                nSquared = nSquared,
                nPlusOne = nPlusOne,
            )
        }

        // ValidateN performs basic checks to make sure the modulus is valid:
        // - log₂(n) = params.BitsPaillier.
        // - n is odd.
        fun validateN(n: BigInteger) : Exception? {
            if (n.signum() <= 0) return IllegalArgumentException("modulus N is nil")
            if (n.bitLength() != BitsPaillier) {
                return IllegalArgumentException("Expected bit length: ${BitsPaillier}, found: ${n.bitLength()}")
            }
            if (!n.testBit(0)) return IllegalArgumentException("Modulus N is even")

            return null
        }
    }

    fun enc(m: BigInteger): Pair<CipherText, BigInteger> {
        val nonce = unitModN(SecureRandomInputStream(SecureRandom()), n)
        return Pair(encWithNonce(m, nonce), nonce)
    }

    fun encWithNonce(m: BigInteger, nonce: BigInteger): CipherText {
        val mAbs = m.abs()
        val nHalf = n.shiftRight(1)

        if (mAbs > nHalf) {
            throw IllegalArgumentException("Encrypt: tried to encrypt message outside of range [-(N-1)/2, …, (N-1)/2]")
        }

        val c = nPlusOne.modPow(m, nSquared)
        val rhoN = nonce.modPow(n, nSquared)

        return CipherText(c.mod(n).multiply(rhoN.mod(n)).mod(n))
    }

    fun validateCiphertexts(vararg cts: CipherText): Boolean {
        for (ct in cts) {
            if (!ct.c.gcd(nSquared).equals(BigInteger.ONE) ) return false
        }
        return true
    }

    override fun equals(other: Any?): Boolean {
        return (other is PublicKey) && n.compareTo(other.n) == 0
    }

    override fun writeTo(outputStream: OutputStream): Long {
        val buf = n.toByteArray()
        outputStream.write(buf)
        return buf.size.toLong()
    }

    override fun domain(): String {
        return "Paillier PublicKey"
    }

    fun modulus(): BigInteger = n

    fun modulusSquared(): BigInteger = nSquared
}
