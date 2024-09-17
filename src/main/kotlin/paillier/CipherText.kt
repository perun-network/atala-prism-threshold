package perun_network.ecdsa_threshold.paillier

import perun_network.ecdsa_threshold.math.unitModN
import java.math.BigInteger

class PaillierCipherText (
    var c : BigInteger
) {
    // Add sets ct to the homomorphic sum ct ⊕ ct₂.
    // ct ← ct•ct₂ (mod N²).
    fun add(pk: PaillierPublic, ct2: PaillierCipherText) : PaillierCipherText {
        val squaredN = pk.nSquared
        c = c.mod(squaredN).multiply(ct2.c.mod(squaredN)).mod(squaredN)
        return this
    }

    // Mul sets ct to the homomorphic multiplication of k ⊙ ct.
    // ct ← ctᵏ (mod N²).
    fun mul(pk: PaillierPublic, k: BigInteger): PaillierCipherText {
            val squaredN = pk.nSquared
            c = c.modPow(k, squaredN)
        return this
    }

    override fun equals(other: Any?): Boolean {
        return (other is PaillierCipherText && c == other.c)
    }

    fun clone(): PaillierCipherText {
        return PaillierCipherText(c)
    }

    // Randomize multiplies the ciphertext's nonce by a newly generated one.
    // ct ← ct ⋅ nonceᴺ (mod N²).
    // If nonce is nil, a random one is generated.
    // The receiver is updated, and the nonce update is returned.
    fun randomize(pk: PaillierPublic, nonce: BigInteger?): BigInteger {
        val squaredN = pk.nSquared
        val finalNonce = nonce ?: unitModN(pk.n)

        // c = c * r ^ N
        val tmp = finalNonce.modPow(pk.n, squaredN)
        c = c.mod(squaredN).multiply(tmp).mod(squaredN)
        return finalNonce
    }

    fun value() : BigInteger = c
}