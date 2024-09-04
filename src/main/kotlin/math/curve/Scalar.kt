package perun_network.ecdsa_threshold.math.curve

import java.io.IOException
import java.math.BigInteger
import kotlin.jvm.Throws

interface Scalar {
    // Encodes the Scalar as Big Endian bytes.
    @Throws(IOException::class)
    fun marshalBinary(): ByteArray
    companion object {
        // Decodes the Scalar from Big Endian bytes.
        @Throws(IOException::class)
        fun unmarshalBinary(data: ByteArray): Scalar {
            throw UnsupportedOperationException("Must be implemented in a subclass")
        }
    }

    // Returns the Curve associated with this kind of Scalar.
    fun curve(): Curve

    // Mutates this Scalar by adding another.
    fun add(other: Scalar): Scalar

    // Mutates this Scalar by subtracting another.
    fun sub(other: Scalar): Scalar

    // Mutates this Scalar by negating it.
    fun negate(): Scalar

    // Mutates this Scalar by multiplying with another.
    fun mul(other: Scalar): Scalar

    // Mutates this Scalar by replacing it with its multiplicative inverse.
    fun invert(): Scalar

    // Checks if this Scalar is equal to 0.
    fun isZero(): Boolean

    // Mutates this Scalar by setting its value to another.
    fun set(other: Scalar) : Scalar

    // Mutates this Scalar by setting its value to a Nat.
    fun setNat(nat: BigInteger): Scalar

    // Acts on a Point with this Scalar, returning a new Point.
    fun act(point: Point): Point

    // Acts on the Base Point with this Scalar, returning a new Point.
    fun actOnBase(): Point

    // Checks if this Scalar is greater than half the order of the group.
    fun isOverHalfOrder(): Boolean

    fun toBigInteger(): BigInteger
}

