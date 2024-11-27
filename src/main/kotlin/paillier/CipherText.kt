package perun_network.ecdsa_threshold.paillier

import java.math.BigInteger

/**
 * Represents a ciphertext in the Paillier cryptosystem.
 *
 * @property c The ciphertext value represented as a [BigInteger].
 *
 * @param c The ciphertext value.
 */
class PaillierCipherText (
    val c : BigInteger
) {
    /**
     * Performs homomorphic multiplication of this ciphertext with another ciphertext.
     *
     * The result is computed as:
     * ct ← ct * ct₂ (mod N²), where N² is the square of the public modulus.
     *
     * @param pk The public key used for this operation, which contains N².
     * @param ct2 The second ciphertext to multiply with this ciphertext.
     * @return A new instance of [PaillierCipherText] representing the result of the multiplication.
     */
    fun modMulNSquared(pk: PaillierPublic, ct2: PaillierCipherText) : PaillierCipherText {
        val squaredN = pk.nSquared
        val cNew = c.mod(squaredN).multiply(ct2.c.mod(squaredN)).mod(squaredN)
        return PaillierCipherText(cNew)
    }

    /**
     * Performs homomorphic exponentiation of this ciphertext by a scalar.
     *
     * The result is computed as:
     * ct ← ctᵏ (mod N²), where k is the scalar.
     *
     * @param pk The public key used for this operation, which contains N².
     * @param k The scalar to which the ciphertext will be raised.
     * @return A new instance of [PaillierCipherText] representing the result of the exponentiation.
     */
    fun modPowNSquared(pk: PaillierPublic, k: BigInteger): PaillierCipherText {
            val squaredN = pk.nSquared
            val new = c.modPow(k, squaredN)
        return PaillierCipherText(new)
    }

    /**
     * Compares this instance with another object for equality.
     *
     * @param other The object to compare this instance with.
     * @return `true` if the specified object is a [PaillierCipherText] with the same ciphertext value; `false` otherwise.
     */
    override fun equals(other: Any?): Boolean {
        return (other is PaillierCipherText && c == other.c)
    }

    /**
     * Creates and returns a clone of this ciphertext.
     *
     * @return A new instance of [PaillierCipherText] that is a copy of this instance.
     */
    fun clone(): PaillierCipherText {
        val cNew = this.c
        return PaillierCipherText(cNew)
    }

    /**
     * Returns the ciphertext value.
     *
     * @return The ciphertext as a [BigInteger].
     */
    fun value() : BigInteger = c
}