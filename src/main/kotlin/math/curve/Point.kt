package perun_network.ecdsa_threshold.math.curve

import kotlinx.serialization.modules.SerializersModule
import java.io.IOException

interface Point {
    // Encodes the Point as Big Endian bytes.
    @Throws(IOException::class)
    fun marshalBinary(): ByteArray

    // Decodes the Point from Big Endian bytes.
    @Throws(IOException::class)
    fun unmarshalBinary(data: ByteArray)

    // Returns the Elliptic Curve group associated with this type of Point.
    fun curve(): Curve

    // Returns a new Point by adding another Point to this one.
    fun add(other: Point): Point

    // Returns a new Point by subtracting another Point from this one.
    fun sub(other: Point): Point

    // Returns the negated version of this Point.
    fun negate(): Point

    // Checks if this Point is the identity element of this group.
    fun isIdentity(): Boolean

    // Returns the x coordinate of this Point as a Scalar, or null if not available.
    fun xScalar(): Scalar?
}



