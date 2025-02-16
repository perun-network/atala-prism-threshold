package perun_network.ecdsa_threshold.pedersen

import perun_network.ecdsa_threshold.math.isValidModN
import java.math.BigInteger

/**
 * Represents the parameters for a Pedersen commitment scheme.
 *
 * @property n The modulus used for calculations in the commitment scheme.
 * @property s The first base used for the commitment.
 * @property t The second base used for the commitment.
 */
data class PedersenParameters(
    val n: BigInteger, // Modulus
    val s: BigInteger,
    val t: BigInteger,
) {
    /**
     * Computes the commitment value using the formula sˣ tʸ (mod N).
     *
     * @param x The exponent for the base s.
     * @param y The exponent for the base t.
     * @return The computed commitment value as a [BigInteger].
     */
    fun calculateCommit(x: BigInteger, y: BigInteger): BigInteger {
        val sx = s.modPow(x, n)
        val ty = t.modPow(y, n)

        return sx.multiply(ty).mod(n)
    }

    /**
     * Verifies the validity of a commitment.
     *
     * Checks whether the equation sᵃ tᵇ ≡ S Tᵉ (mod N) holds true.
     *
     * @param a The exponent for the base s in the left-hand side of the equation.
     * @param b The exponent for the base t in the left-hand side of the equation.
     * @param e The exponent for the base T in the right-hand side of the equation.
     * @param S The commitment value on the left-hand side.
     * @param T The commitment value on the right-hand side.
     * @return `true` if the commitment is valid, `false` otherwise.
     */
    fun verifyCommit(a: BigInteger, b: BigInteger, e: BigInteger, S: BigInteger, T: BigInteger): Boolean {
        if (!isValidModN(n, S, T)) {
            return false
        }

        val sa = s.modPow(a, n)
        val tb = t.modPow(b, n)
        val lhs = sa.multiply(tb).mod(n) // lhs = sᵃ⋅tᵇ (mod N)

        val te = T.modPow(e, n) // Tᵉ (mod N)
        val rhs = te.multiply(S).mod(n) // rhs = S⋅Tᵉ (mod N)
        return lhs == rhs
    }

    /**
     * Serializes the Pedersen parameters to a byte array.
     *
     * @return The serialized byte array representation.
     */
    fun toByteArray(): ByteArray {
        // Convert each BigInteger to its byte array representation
        val nBytes = n.toByteArray()
        val sBytes = s.toByteArray()
        val tBytes = t.toByteArray()

        // Helper function to convert an integer size to a 4-byte array
        fun Int.toByteArray(): ByteArray = byteArrayOf(
            (this shr 24).toByte(),
            (this shr 16).toByte(),
            (this shr 8).toByte(),
            this.toByte()
        )

        // Combine the lengths and the actual byte arrays
        return nBytes.size.toByteArray() + nBytes + sBytes.size.toByteArray() + sBytes +
                tBytes.size.toByteArray() + tBytes
    }
}