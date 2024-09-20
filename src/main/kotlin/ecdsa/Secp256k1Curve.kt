package perun_network.ecdsa_threshold.ecdsa

import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
import java.math.BigInteger

// Define the secp256k1 curve parameters
val P: BigInteger = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16) // Prime modulus
val A: BigInteger = BigInteger.ZERO // Curve parameter A (for secp256k1)
val B: BigInteger = BigInteger("7") // Curve parameter B
val N: BigInteger = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16) // Order of the base point
val GX = BigInteger("79BE667EF9DCBBAC55A06295CE870B70A0B5A0AA3A2C7CF24E9FBE6D4C4F9BC", 16)
val GY = BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17D448A68554199C47D08F4CF0CBB", 16)

fun secp256k1Order() : BigInteger {
    return P
}

data class Point(
    val x: BigInteger,
    val y: BigInteger
) {
    init {
        require(x >= BigInteger.ZERO && x < P) { "x-coordinate must be in range" }
        require(y >= BigInteger.ZERO && y < P) { "y-coordinate must be in range" }
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
            // Handle special cases
            if (this.isIdentity()) return other // Adding identity element
            if (other.isIdentity()) return this // Adding identity element

            // Check if the points are inverses
            if (this.x == other.x && (this.y.add(other.y).mod(P) == BigInteger.ZERO)) {
                return Point(BigInteger.ZERO, BigInteger.ZERO) // Return identity element
            }

            // Check if points are the same (point doubling case)
            if (this.x == other.x && this.y == other.y) {
                return this.double() // Use point doubling
            }

            // Regular point addition
            val lambda = (other.y.subtract(this.y).multiply(other.x.subtract(this.x).modInverse(P))).mod(P)
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

    // Scalar multiplication
    fun multiply(scalar: Scalar): Point {
        var result = Point(BigInteger.ZERO, BigInteger.ZERO) // Point at infinity
        var point = this
        var k = scalar.value

        while (k > BigInteger.ZERO) {
            if (k.and(BigInteger.ONE) == BigInteger.ONE) {
                result = result.add(point)
            }
            point = point.double()
            k = k.shiftRight(1)
        }

        return result
    }

    // isIdentity checks if this is the identity element of this group.
    fun isIdentity() : Boolean {
        return this.x == BigInteger.ZERO || this.y == BigInteger.ZERO
    }

}

fun byteArrayToPoint(bytes: ByteArray): Point {
    require(bytes.size == 65)
    val x = BigInteger(1, bytes.copyOfRange(1, 33))
    val y = BigInteger(1, bytes.copyOfRange(33, bytes.size))
    return Point(x, y)
}

fun newBasePoint(): Point {
    val g = Hex.decode("0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8".lowercase())
    val base = Secp256k1.pubkeyParse(g)
    return byteArrayToPoint(base)
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
// Function to add two points on the elliptic curve
fun pointAdd(p1: Point, p2: Point): Point {
    val (x1, y1) = p1
    val (x2, y2) = p2

    if (x1 == x2 && y1 == y2) {
        return pointDouble(p1)
    }

    val lambda = (y2 - y1).multiply((x2 - x1).modInverse(P)).mod(P)
    val x3 = (lambda.multiply(lambda).subtract(x1).subtract(x2)).mod(P)
    val y3 = (lambda.multiply(x1.subtract(x3)).subtract(y1)).mod(P)

    return Point(x3, y3)
}

// Function to double a point on the elliptic curve
fun pointDouble(p: Point): Point {
    val (x1, y1) = p
    val lambda = (BigInteger.valueOf(3).multiply(x1.multiply(x1)).add(A)).multiply((BigInteger.valueOf(2).multiply(y1)).modInverse(P)).mod(P)
    val x3 = (lambda.multiply(lambda).subtract(BigInteger.valueOf(2).multiply(x1))).mod(P)
    val y3 = (lambda.multiply(x1.subtract(x3)).subtract(y1)).mod(P)

    return Point(x3, y3)
}

// Function to perform scalar multiplication
fun scalarMultiply(k: Scalar, point: Point): Point {
    var result = Point(BigInteger.ZERO, BigInteger.ZERO) // Start with the identity element (point at infinity)
    var addend = point
    var kValue = k.value // Work with a copy of the scalar's value to avoid modifying the original Scalar object

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
    }

    fun toPrivateKey(): PrivateKey {
        val scalarBytes = bigIntegerToByteArray(value)
        return PrivateKey.newPrivateKey(scalarBytes)
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