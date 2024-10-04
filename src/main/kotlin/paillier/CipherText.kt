package perun_network.ecdsa_threshold.paillier

import perun_network.ecdsa_threshold.math.sampleUnitModN
import java.math.BigInteger

class PaillierCipherText (
    val c : BigInteger
) {
    // Add sets ct to the homomorphic sum ct ⊕ ct₂.
    // ct ← ct•ct₂ (mod N²).
    fun modMulNSquared(pk: PaillierPublic, ct2: PaillierCipherText) : PaillierCipherText {
        val squaredN = pk.nSquared
        val cNew = c.mod(squaredN).multiply(ct2.c.mod(squaredN)).mod(squaredN)
        return PaillierCipherText(cNew)
    }

    // Mul sets ct to the homomorphic multiplication of k ⊙ ct.
    // ct ← ctᵏ (mod N²).
    fun modPowNSquared(pk: PaillierPublic, k: BigInteger): PaillierCipherText {
            val squaredN = pk.nSquared
            val new = c.modPow(k, squaredN)
        return PaillierCipherText(new)
    }

    override fun equals(other: Any?): Boolean {
        return (other is PaillierCipherText && c == other.c)
    }

    fun clone(): PaillierCipherText {
        val cNew = this.c
        return PaillierCipherText(cNew)
    }

    fun value() : BigInteger = c
}