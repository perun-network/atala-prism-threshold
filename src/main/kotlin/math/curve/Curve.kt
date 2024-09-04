package perun_network.ecdsa_threshold.math.curve

import java.math.BigInteger

interface Curve {
    // Creates an identity point.
    fun newPoint(): Point

    // Creates the generator of this group.
    fun newBasePoint(): Point

    // Creates a scalar with the value of 0.
    fun newScalar(): Scalar

    // Returns the name of this curve.
    fun name(): String

    // Returns the number of significant bits in a scalar.
    fun scalarBits(): Int

    // Returns the number of random bytes needed to sample a scalar through modular reduction.
    fun safeScalarBytes(): Int

    // Returns a Modulus holding the order of this group.
    fun order(): BigInteger

}

/**
 * MakeInt converts a scalar into an Int.
 */
fun makeInt(s: Scalar): BigInteger {
    val bytes = s.marshalBinary()
    return BigInteger(bytes)
}

/**
 * FromHash converts a hash value to a Scalar.
 *
 * There is some disagreement about how this should be done.
 * [NSA] suggests that this is done in the obvious
 * manner, but [SECG] truncates the hash to the bit-length of the curve order
 * first. We follow [SECG] because that's what OpenSSL does. Additionally,
 * OpenSSL right shifts excess bits from the number if the hash is too large
 * and we mirror that too.
 *
 * Taken from crypto/ecdsa.
 */
fun fromHash(curve: Curve, hash: ByteArray): Scalar {
    val order = curve.order()
    val orderBits = order.bitLength()
    val orderBytes = (orderBits + 7) / 8
    val h = if (hash.size > orderBytes) hash.copyOf(orderBytes) else hash
    val nat = BigInteger(h)
    val excess = h.size * 8 - orderBits
    if (excess > 0) {
        nat.shiftRight(excess)
    }
    return curve.newScalar().setNat(nat)
}