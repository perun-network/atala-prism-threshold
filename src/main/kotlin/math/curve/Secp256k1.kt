package perun_network.ecdsa_threshold.math.curve

import fr.acinq.secp256k1.Secp256k1
import fr.acinq.secp256k1.Hex
import java.math.BigInteger
import java.util.Arrays

object CurveSecp256k1 : Curve {

    private val secp256k1 = Secp256k1.get()

    private val secp256k1BaseX: ByteArray = Hex.decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    private val secp256k1BaseY: ByteArray = Hex.decode("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
    private val secp256k1Order: BigInteger = BigInteger(1, Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"))

    override fun newPoint(): Point = Secp256k1Point()

    override fun newBasePoint(): Point {
        val z = ByteArray(32)
        z[31] = 1
        return Secp256k1Point(secp256k1BaseX, secp256k1BaseY, z)
    }



    override fun newScalar(): Scalar = Secp256k1Scalar()

    override fun scalarBits(): Int = 256

    override fun safeScalarBytes(): Int = 32

    override fun order(): BigInteger = secp256k1Order

    override fun name(): String = "secp256k1"

    class Secp256k1Scalar() : Scalar {
        private var value: BigInteger = BigInteger.ZERO

        constructor(value: BigInteger) : this() {
            this.value = value.mod(secp256k1Order)
        }

        override fun add(other: Scalar): Scalar {
            other as? Secp256k1Scalar ?: throw IllegalArgumentException("failed to convert Secp256K1 Scalar")
            return Secp256k1Scalar(this.value.add(other.value).mod(secp256k1Order))
        }

        override fun sub(other: Scalar): Scalar {
            other as? Secp256k1Scalar ?: throw IllegalArgumentException("failed to convert Secp256K1 Scalar")
            return Secp256k1Scalar(this.value.subtract(other.value).mod(secp256k1Order))
        }

        override fun mul(other: Scalar): Scalar {
            other as? Secp256k1Scalar ?: throw IllegalArgumentException("failed to convert Secp256K1 Scalar")
            return Secp256k1Scalar(this.value.multiply(other.value).mod(secp256k1Order))
        }

        override fun invert(): Secp256k1Scalar {
            return Secp256k1Scalar(this.value.modInverse(secp256k1Order))
        }

        override fun negate(): Secp256k1Scalar {
            return Secp256k1Scalar(secp256k1Order.subtract(this.value))
        }

        override fun isOverHalfOrder(): Boolean {
            return this.value > secp256k1Order.shiftRight(1)
        }

        override fun toBigInteger(): BigInteger {
            return value
        }

        override fun isZero(): Boolean {
            return this.value == BigInteger.ZERO
        }

        override fun set(other: Scalar) : Scalar {
            other as? Secp256k1Scalar ?: throw IllegalArgumentException("failed to convert Secp256K1 Scalar")
            value = other.value
            return this
        }

        fun set(that: Secp256k1Scalar): Secp256k1Scalar {
            this.value = that.value
            return this
        }

        override fun setNat(nat: BigInteger): Secp256k1Scalar {
            this.value = nat.mod(secp256k1Order)
            return this
        }

        override fun act(point: Point): Secp256k1Point {
            val pubKey = secp256k1.pubkeyParse(point.xBytes(), point.yBytes())
            val res = secp256k1.privKeyTweakMul(pubKey, this.value.toByteArray())
            return Secp256k1Point(secp256k1.pubKeySerialize(res, false))
        }

        override fun actOnBase(): Secp256k1Point {
            val res = secp256k1.privKeyTweakMul(secp256k1BaseX + secp256k1BaseY, this.value.toByteArray())
            return Secp256k1Point(secp256k1.pubKeySerialize(res, false))
        }

        override fun marshalBinary(): ByteArray = value.toByteArray()
        override fun curve(): Curve {
            return CurveSecp256k1
        }

        companion object {
            fun unmarshalBinary(data: ByteArray): Secp256k1Scalar {
                return Secp256k1Scalar(BigInteger(1, data))
            }
        }
    }

    class Secp256k1Point() : Point {
        var x: ByteArray = ByteArray(32)
        var y: ByteArray = ByteArray(32)
        var z: ByteArray = ByteArray(32)

        fun setByteSlice(b: ByteArray): Boolean {
            // Ensure the byte array is at most 32 bytes long
            val b32 = ByteArray(32)
            val length = minOf(b.size, 32)

            // Copy the bytes into the last part of the 32-byte array
            System.arraycopy(b, 0, b32, 32 - length, length)

            // Convert the byte array to BigInteger
            val inputValue = BigInteger(1, b32)

            // Check if the value is greater than or equal to the field prime (indicating overflow)
            val overflow = inputValue >= fieldPrime

            // Set the internal value as the byte representation of the modulus
            value = inputValue.mod(fieldPrime).toByteArray()

            // Pad or truncate to 32 bytes
            if (value.size < 32) {
                value = ByteArray(32 - value.size) { 0 } + value
            } else if (value.size > 32) {
                value = value.takeLast(32).toByteArray()
            }

            return overflow
        }

        constructor(x: ByteArray, y: ByteArray, z: ByteArray) : this() {
            this.x = x
            this.y = y
        }

        constructor(pubKey: ByteArray) : this() {
            val parsed = secp256k1.pubKeyParse(pubKey, false)
            this.x = Arrays.copyOfRange(parsed, 0, 32)
            this.y = Arrays.copyOfRange(parsed, 32, 64)
        }

        fun xBytes(): ByteArray = x

        fun yBytes(): ByteArray = y

        override fun marshalBinary(): ByteArray {
            return secp256k1.pubKeySerialize(x + y, false)
        }

        override fun unmarshalBinary(data: ByteArray) {
            val parsed = secp256k1.pubKeyParse(data, false)
            this.x = Arrays.copyOfRange(parsed, 0, 32)
            this.y = Arrays.copyOfRange(parsed, 32, 64)
        }

        override fun curve(): Curve {
            return CurveSecp256k1
        }

        override fun add(that: Point): Point {
            val pubKey1 = secp256k1.pubKeyParse(this.marshalBinary(), false)
            val pubKey2 = secp256k1.pubKeyParse(that.marshalBinary(), false)
            val res = secp256k1.pubKeyCombine(listOf(pubKey1, pubKey2))
            return Secp256k1Point(secp256k1.pubKeySerialize(res, false))
        }

        override fun sub(that: Point): Point {
            return this.add(that.negate())
        }

        fun set(that: Secp256k1Point): Point {
            this.x = that.x
            this.y = that.y
            return this
        }

        override fun negate(): Point {
            val negated = secp256k1.pubKeyNegate(this.marshalBinary())
            return Secp256k1Point(negated)
        }

        override fun equals(that: Any?): Boolean {
            return this.x.contentEquals(that.x) && this.y.contentEquals(that.y)
        }

        override fun isIdentity(): Boolean {
            return x.all { it == 0.toByte() } && y.all { it == 0.toByte() }
        }

        fun hasEvenY(): Boolean {
            return y.last() % 2 == 0
        }

        override fun xScalar(): Scalar {
            return Secp256k1Scalar(BigInteger(1, x))
        }
    }
}