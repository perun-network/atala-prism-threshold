package perun_network.ecdsa_threshold.ecdsa

import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
import java.math.BigInteger
import kotlin.math.max

// Define the secp256k1 curve parameters
val P: BigInteger = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F".lowercase(), 16) // Prime modulus
val A: BigInteger = BigInteger.ZERO // Curve parameter A (for secp256k1)
val B: BigInteger = BigInteger("7") // Curve parameter B
val N: BigInteger = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16) // Order of the base point
val GX = BigInteger("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16)
val GY = BigInteger("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16)

fun secp256k1Order() : BigInteger {
    return N
}

data class Point(
    val x: BigInteger,
    val y: BigInteger
) {
    init {
        require(x >= BigInteger.ZERO && x < P) { "x-coordinate must be in range" }
        require(y >= BigInteger.ZERO && y < P) { "y-coordinate must be in range" }
    }

    fun xScalar() : Scalar {
        return Scalar(x.mod(N))
    }

    fun inverse(): Point {
        // Inverse of the point is (x, -y mod P)
        val yInverse = P.subtract(y).mod(P)
        return Point(x, yInverse)
    }

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

    // Point addition
    fun add(other: Point): Point {
        if (this.isIdentity()) return other // Adding identity element
        if (other.isIdentity()) return this // Adding identity element

        // Check if the points are inverses
        if (this.x == other.x && (this.y.add(other.y).mod(P) == BigInteger.ZERO)) {
            return Point(BigInteger.ZERO, BigInteger.ZERO) // Return identity element (point at infinity)
        }

        val lambda: BigInteger
        // Check if points are the same (point doubling case)
        if (this == other) {
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

    // Point doubling
    fun double(): Point {
        val lambda = (x.pow(2).multiply(BigInteger.valueOf(3)).add(A)).multiply(y.multiply(BigInteger.valueOf(2)).modInverse(P)).mod(P)
        val x3 = (lambda.pow(2).subtract(x.multiply(BigInteger.valueOf(2)))).mod(P)
        val y3 = (lambda.multiply(x.subtract(x3)).subtract(y)).mod(P)
        return Point(x3, y3)
    }

    // isIdentity checks if this is the identity element of this group.
    fun isIdentity() : Boolean {
        return this.x == BigInteger.ZERO || this.y == BigInteger.ZERO
    }

    override fun equals(other: Any?): Boolean {
        return (other is Point) && (x == other.x && y == other.y)
    }

}

fun byteArrayToPoint(bytes: ByteArray): Point {
    require(bytes.size == 65)
    val x = BigInteger(1, bytes.copyOfRange(1, 33))
    val y = BigInteger(1, bytes.copyOfRange(33, bytes.size))
    return Point(x, y)
}

fun newBasePoint(): Point {
    return Point(
        x = GX,
        y = GY
    )
}

fun newPoint() : Point {
    return Point(BigInteger.ZERO, BigInteger.ZERO)
}

// Function to convert BigInteger to a 32-byte array
fun bigIntegerToByteArray(bi: BigInteger): ByteArray {
    val bytes = bi.toByteArray()
    return if (bytes.size == 32) {
        bytes
    } else if (bytes.size < 32) {
        ByteArray(32) { i -> if (i < 32 - bytes.size) 0 else bytes[i - (32 - bytes.size)] }
    } else {
        bytes.copyOfRange(bytes.size - 32, bytes.size)
    }
}


// Function to perform scalar multiplication
fun scalarMultiply(k: Scalar, point: Point): Point {
    var kValue = k.value
    var effectivePoint = point

    // Handle negative scalar: if k is negative, multiply by the inverse of the point
    if (kValue < BigInteger.ZERO) {
        kValue = kValue.mod(secp256k1Order()) // Use the absolute value of the scalar
    }

    var result = Point(BigInteger.ZERO, BigInteger.ZERO) // Start with the identity element (point at infinity)
    var addend = effectivePoint

    while (kValue != BigInteger.ZERO) {
        if (kValue.and(BigInteger.ONE) == BigInteger.ONE) {
            result = result.add(addend) // Add the current addend if the current bit is 1
        }
        addend = addend.double() // Double the point
        kValue = kValue.shiftRight(1) // Shift right to process the next bit of the scalar
    }

    return result
}

data class Scalar (
    var value: BigInteger,
) {
    companion object {
        fun zero() : Scalar {
            return Scalar(BigInteger.ZERO)
        }

        fun scalarFromInt(value : Int) : Scalar {
            return Scalar(value.toBigInteger().mod(N))
        }

        fun scalarFromHash(h: ByteArray) : Scalar {
            val orderBits = secp256k1Order().bitLength()
            val orderBytes = (orderBits + 7) / 8

            // Truncate the hash if it's larger than the number of bytes in the curve order
            val hash = if (h.size > orderBytes) h.sliceArray(0 until orderBytes) else h

            // Convert the hash bytes to a BigInteger
            var s = BigInteger(1, hash)  // BigInteger(1, ...) ensures it's positive

            // Check if the hash is longer than the curve's bit-length, and shift it
            val excess = hash.size * 8 - orderBits
            if (excess > 0) {
                s = s.shiftRight(excess)
            }

            // Create a new Scalar from the adjusted value
            return Scalar(s.mod(secp256k1Order()))
        }
    }

    fun isZero() : Boolean {
        return value == BigInteger.ZERO
    }

    fun toPrivateKey(): PrivateKey {
        val scalarBytes = bigIntegerToByteArray(value)
        return PrivateKey.newPrivateKey(scalarBytes)
    }

    fun toByteArray() : ByteArray {
        return bigIntegerToByteArray(value)
    }

    fun invert() : Scalar {
        return Scalar(value.modInverse(N))
    }

    // Multiply this scalar with another scalar
    fun multiply(other: Scalar): Scalar {
        val product = value.multiply(other.value).mod(N)
        return Scalar(product)
    }

    // Add this scalar with another scalar
    fun add(other: Scalar): Scalar {
        val sum = value.add(other.value).mod(N)
        return Scalar(sum)
    }

    // Subtract this scalar by another scalar
    fun subtract(other: Scalar): Scalar {
        val difference = value.subtract(other.value).mod(N)
        return Scalar(difference)
    }

    // Multiply this scalar by an integer
    fun multiplyByInteger(k: BigInteger): Scalar {
        val product = value.multiply(k).mod(N)
        return Scalar(product)
    }

    fun actOnBase() : Point {
        return scalarMultiply(this, newBasePoint())
    }

    fun act(point : Point) : Point {
        return scalarMultiply(this, point)
    }
}