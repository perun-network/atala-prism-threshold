package perun_network.ecdsa_threshold.ecdsa

import java.math.BigInteger

/**
 * The prime modulus (P) of the secp256k1 curve.
 */
val P: BigInteger = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F".lowercase(), 16)

/**
 * The curve parameter A of the secp256k1 curve.
 */
val A: BigInteger = BigInteger.ZERO

/**
 * The curve parameter B of the secp256k1 curve.
 */
val B: BigInteger = BigInteger("7") // Curve parameter B

/**
 * The order (N) of the base point of the secp256k1 curve.
 */
val N: BigInteger = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141".lowercase(), 16) // Order of the base point

/**
 * The x-coordinate of the base point (G) of the secp256k1 curve.
 */
val GX = BigInteger("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16)

/**
 * The y-coordinate of the base point (G) of the secp256k1 curve.
 */
val GY = BigInteger("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16)

/**
 * Returns the order of the secp256k1 curve.
 *
 * @return The order of the secp256k1 curve as a BigInteger.
 */
fun secp256k1Order() : BigInteger {
    return N
}

/**
 * Represents a point on the secp256k1 elliptic curve.
 *
 * @property x The x-coordinate of the point.
 * @property y The y-coordinate of the point.
 */
data class Point(
    val x: BigInteger,
    val y: BigInteger
) {
    init {
        require(x >= BigInteger.ZERO && x < P) { "x-coordinate must be in range" }
        require(y >= BigInteger.ZERO && y < P) { "y-coordinate must be in range" }
    }


    /**
     * Returns the x-coordinate of this point as a Scalar.
     *
     * @return The x-coordinate as a Scalar.
     */
    fun xScalar() : Scalar {
        return Scalar(x.mod(N))
    }

    /**
     * Returns the inverse of this point.
     * The inverse is defined as (x, -y mod P).
     *
     * @return The inverse of this point.
     */
    fun inverse(): Point {
        // Inverse of the point is (x, -y mod P)
        val yInverse = P.subtract(y).mod(P)
        return Point(x, yInverse)
    }

    /**
     * Converts this point into a PublicKey.
     *
     * @return The corresponding PublicKey.
     */
    fun toPublicKey(): PublicKey {
        val xBytes = bigIntegerToByteArray(x)
        val yBytes = bigIntegerToByteArray(y)

        val data = ByteArray(65).apply {
            this[0] = 0x04.toByte() // Uncompressed format prefix
            System.arraycopy(xBytes,0, this, 1, 32)
            System.arraycopy(yBytes, 0, this, 33, 32)
        }
        return PublicKey.newPublicKey(data)
    }

    fun toByteArray() : ByteArray {
        val xBytes = bigIntegerToByteArray(x)
        val yBytes = bigIntegerToByteArray(y)
        return xBytes + yBytes
    }

    /**
     * Adds this point to another point on the curve.
     *
     * @param other The other point to add.
     * @return The resulting point from the addition.
     */
    fun add(other: Point): Point {
        if (this.isIdentity()) return other // Adding identity element
        if (other.isIdentity()) return this // Adding identity element

        // Check if the points are inverses (P1 + (-P1) = identity element)
        if (this.x == other.x && (this.y.add(other.y).mod(P) == BigInteger.ZERO)) {
            return Point(BigInteger.ZERO, BigInteger.ZERO) // Return identity element (point at infinity)
        }

        val lambda: BigInteger
        // Point doubling (this == other)
        if (this == other) {
            // Ensure y != 0 to avoid division by zero
            if (this.y == BigInteger.ZERO) return Point(BigInteger.ZERO, BigInteger.ZERO) // Return identity element

            // Point doubling formula for lambda
            lambda = (this.x.pow(2).multiply(BigInteger.valueOf(3)).add(A))
                .multiply(this.y.multiply(BigInteger.valueOf(2)).modInverse(P)).mod(P)
        } else {
            // Regular point addition formula for lambda
            lambda = (other.y.subtract(this.y).multiply(other.x.subtract(this.x).modInverse(P))).mod(P)
        }

        // Calculate new x and y coordinates
        val x3 = (lambda.pow(2).subtract(this.x).subtract(other.x)).mod(P)
        val y3 = (lambda.multiply(this.x.subtract(x3)).subtract(this.y)).mod(P)

        return Point(x3, y3)
    }

    /**
     * Doubles this point on the curve.
     *
     * @return The resulting point from the doubling operation.
     */
    fun double(): Point {
        // Handle the edge case: if y == 0, doubling returns the identity element
        if (this.y == BigInteger.ZERO) return Point(BigInteger.ZERO, BigInteger.ZERO) // Return identity element

        // Compute lambda for point doubling
        val lambda = (x.pow(2).multiply(BigInteger.valueOf(3)).add(A))
            .multiply(y.multiply(BigInteger.valueOf(2)).modInverse(P)).mod(P)

        // Calculate new x and y coordinates
        val x3 = (lambda.pow(2).subtract(x.multiply(BigInteger.valueOf(2)))).mod(P)
        val y3 = (lambda.multiply(x.subtract(x3)).subtract(y)).mod(P)

        return Point(x3, y3)
    }

    /**
     * Checks if this point is the identity element (point at infinity).
     *
     * @return True if this point is the identity element, otherwise false.
     */
    fun isIdentity() : Boolean {
        return this.x == BigInteger.ZERO || this.y == BigInteger.ZERO
    }


    /**
     * Checks equality between this [Point] and another object.
     *
     * @param other The object to compare with.
     * @return `true` if the other object is a [Point] with the same byte array, otherwise `false`.
     */
    override fun equals(other: Any?): Boolean {
        return (other is Point) && (x == other.x && y == other.y)
    }

    /**
     * Checks if this point lies on the secp256k1 curve.
     *
     * @return True if the point lies on the curve, otherwise false.
     */
    fun isOnCurve(): Boolean {
        if (this.isIdentity()) return true // Identity point is considered on the curve

        // Calculate y^2 mod P
        val leftSide = this.y.pow(2).mod(P)

        // Calculate x^3 + b mod P (since a = 0, we can skip the ax term)
        val rightSide = (this.x.pow(3).add(BigInteger.valueOf(7))).mod(P)

        // Check if both sides are equal
        return leftSide == rightSide
    }

}

/**
 * Converts a byte array into a Point on the secp256k1 curve.
 *
 * @param bytes The byte array to convert.
 * @return The resulting Point.
 */
fun byteArrayToPoint(bytes: ByteArray): Point {
    require(bytes.size == 65)
    val x = BigInteger(bytes.copyOfRange(1, 33)).mod(P)
    val y = BigInteger(bytes.copyOfRange(33, bytes.size)).mod(P)
    return Point(x, y)
}

/**
 * Creates a new base point (G) on the secp256k1 curve.
 *
 * @return The base point (G).
 */
fun newBasePoint(): Point {
    return Point(
        x = GX,
        y = GY
    )
}

/**
 * Creates a new identity point (0,0) on the secp256k1 curve.
 *
 * @return The identity point.
 */
fun newPoint() : Point {
    return Point(BigInteger.ZERO, BigInteger.ZERO)
}

/**
 * Converts a BigInteger into a 32-byte array.
 *
 * @param bi The BigInteger to convert.
 * @return The resulting byte array.
 */
fun bigIntegerToByteArray(bi: BigInteger): ByteArray {
    val bytes = bi.toByteArray()

    return when {
        // If it's already 32 bytes, return it
        bytes.size == 32 -> bytes
        // If it's smaller, pad with leading zeros
        bytes.size < 32 -> ByteArray(32) { i -> if (i < 32 - bytes.size) 0 else bytes[i - (32 - bytes.size)] }
        // If it's larger, truncate it to the first 32 bytes
        bytes.size > 32 -> bytes.copyOfRange(bytes.size - 32, bytes.size)  // Handle cases where sign bit causes extra byte
        else -> bytes
    }
}

/**
 * Performs scalar multiplication on a point with a scalar.
 *
 * @param k The scalar value.
 * @param point The point to multiply.
 * @return The resulting point.
 */
fun scalarMultiply(k: Scalar, point: Point): Point {
    var kValue = k.value
    var effectivePoint = point

    // Handle negative scalar: reflect the point across the x-axis if k is negative
    if (kValue < BigInteger.ZERO) {
        kValue = kValue.abs().mod(secp256k1Order()) // Convert to positive scalar
        effectivePoint = Point(effectivePoint.x, effectivePoint.y.negate().mod(P)) // Reflect over the x-axis
    }

    var result = Point(BigInteger.ZERO, BigInteger.ZERO) // Use proper representation of point at infinity here
    var addend = effectivePoint

    while (kValue != BigInteger.ZERO) {
        if (kValue.and(BigInteger.ONE) == BigInteger.ONE) {
            result = result.add(addend) // Add the current addend if the current bit is 1
        }
        addend = addend.double() // Double the point
        kValue = kValue.shiftRight(1) // Shift right to process the next bit of the scalar
    }

    return Point(result.x.mod(P), result.y.mod(P)) // Return result mod P
}

/**
 * Represents a scalar value for secp256k1 operations.
 *
 * @property value The scalar value as a BigInteger.
 */
data class Scalar (
    var value: BigInteger,
) {
    companion object {
        /**
         * Returns a zero scalar.
         *
         * @return A scalar with value zero.
         */
        fun zero() : Scalar {
            return Scalar(BigInteger.ZERO)
        }

        /**
         * Creates a scalar from a BigInteger value.
         *
         * @param value The integer value.
         * @return The corresponding scalar.
         */
        fun scalarFromBigInteger(value: BigInteger): Scalar {
            return Scalar(value.mod(N))
        }

        /**
         * Creates a scalar from an integer value.
         *
         * @param value The integer value.
         * @return The corresponding scalar.
         */
        fun scalarFromInt(value : Int) : Scalar {
            return Scalar(value.toBigInteger().mod(N))
        }


        /**
         * Creates a scalar from a byte array.
         *
         * @param h The byte array.
         * @return The corresponding scalar.
         */
        fun scalarFromByteArray(h: ByteArray) : Scalar {
            // Convert the full hash directly to a BigInteger, treating it as positive
            val hashBigInt = BigInteger(1, h)

            // Take the modulo N to ensure the scalar is within the curve's order
            return Scalar(hashBigInt.mod(secp256k1Order()))
        }

    }

    /**
     * Checks if the scalar is zero.
     *
     * @return True if the scalar is zero, otherwise false.
     */
    fun isZero() : Boolean {
        return value == BigInteger.ZERO
    }


    /**
     * Converts the scalar to a private key.
     *
     * @return The corresponding private key.
     */
    fun toPrivateKey(): PrivateKey {
        val scalarBytes = bigIntegerToByteArray(value)
        return PrivateKey.newPrivateKey(scalarBytes)
    }


    /**
     * Converts the scalar to a byte array.
     *
     * @return The scalar as a 32-byte array.
     */
    fun toByteArray() : ByteArray {
        return bigIntegerToByteArray(value)
    }

    /**
     * Inverts the scalar (modular inverse relative to the curve order).
     *
     * @return The inverse of the scalar.
     */
    fun invert() : Scalar {
        return Scalar(value.modInverse(N))
    }

    /**
     * Multiplies this scalar by another scalar.
     *
     * @param other The other scalar to multiply with.
     * @return The resulting scalar.
     */
    fun multiply(other: Scalar): Scalar {
        val product = value.multiply(other.value.mod(N)).mod(N)
        return Scalar(product)
    }

    /**
     * Adds this scalar to another scalar.
     *
     * @param other The other scalar to add.
     * @return The resulting scalar.
     */
    fun add(other: Scalar): Scalar {
        val sum = value.add(other.value.mod(N)).mod(N)
        return Scalar(sum)
    }

    /**
     * Subtracts another scalar from this scalar.
     *
     * @param other The other scalar to subtract.
     * @return The resulting scalar.
     */
    fun subtract(other: Scalar): Scalar {
        val difference = value.subtract(other.value) // Directly subtract
        return Scalar(difference.add(N).mod(N)) // Normalize to ensure non-negative result
    }

    /**
     * Performs scalar multiplication of this scalar on the base point of the curve.
     *
     * @return The resulting point from scalar multiplication.
     */
    fun actOnBase() : Point {
        return scalarMultiply(this, newBasePoint())
    }

    /**
     * Performs scalar multiplication of this scalar on the given point.
     *
     * @param point The point to multiply with.
     * @return The resulting point from scalar multiplication.
     */
    fun act(point : Point) : Point {
        return scalarMultiply(this, point)
    }
}