package perun_network.ecdsa_threshold.math.polynomial

import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import perun_network.ecdsa_threshold.hash.WriterToWithDomain
import perun_network.ecdsa_threshold.math.curve.Curve
import perun_network.ecdsa_threshold.math.curve.Point
import perun_network.ecdsa_threshold.math.curve.Scalar
import java.io.OutputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder

data class RawExponentData (
    val isConstant: Boolean,
    val coefficients: List<Point>
)

@Serializable
class Exponent (
    val group: Curve,
    var isConstant: Boolean,
    var coefficients: List<Point>
) :WriterToWithDomain {

    // newPolynomialExponent generates an Exponent polynomial F(X) = [secret + a₁•X + … + aₜ•Xᵗ]•G,
    // with coefficients in 𝔾, and degree t.
    companion object {
        fun newPolynomialExponent(polynomial: Polynomial): Exponent {
            val coefficients = polynomial.coefficients.map { it.actOnBase() }
            return Exponent(
                group = polynomial.group,
                isConstant = polynomial.coefficients[0].isZero(),
                coefficients = coefficients
            )
        }

        // Sum creates a new Exponent by summing a list of existing ones.
        fun sum(polynomials: List<Exponent>): Exponent {
            val first = polynomials.first()
            return polynomials.drop(1).fold(first) { acc, exp -> acc.add(exp) }
        }

        fun emptyExponent(group: Curve): Exponent = Exponent(group, isConstant = false, coefficients = emptyList())

    }

    // Evaluate returns F(x) = [secret + a₁•x + … + aₜ•xᵗ]•G.
    fun evaluate(x: Scalar): Point {
        var result = group.newPoint()

        for (i in coefficients.indices.reversed()) {
            result = x.act(result).add(coefficients[i])
        }

        if (isConstant) {
            result = x.act(result)
        }

        return result
    }

    // Evaluate using the classic method
    fun evaluateClassic(x: Scalar): Point {
        var xPower = group.newScalar().setNat(BigInteger.ONE)
        var result = group.newPoint()

        if (isConstant) {
            xPower = xPower.mul(x)
        }

        for (i in coefficients.indices) {
            val tmp = xPower.act(coefficients[i])
            result = result.add(tmp)
            xPower = xPower.mul(x)
        }
        return result
    }

    // Degree returns the degree t of the polynomial.
    fun degree(): Int {
        return if (isConstant) coefficients.size else coefficients.size - 1
    }

    fun copy(): Exponent {
        return Exponent(
            group = group,
            isConstant = isConstant,
            coefficients = coefficients.toList()
        )
    }

    // Constant returns the constant coefficient of the polynomial 'in the exponent'.
    fun constant(): Point {
        return if (isConstant) group.newPoint() else coefficients[0]
    }

    // Add polynomials
    fun add(other: Exponent): Exponent {
        require(coefficients.size == other.coefficients.size) { "Polynomials must have the same degree" }
        require(isConstant == other.isConstant) { "Polynomials must have the same isConstant value" }

        val newCoefficients = coefficients.zip(other.coefficients) { a, b -> a.add(b) }
        return Exponent(group, isConstant, newCoefficients)
    }

    override fun writeTo(outputStream: OutputStream): Long {
        val data = marshalBinary()
        outputStream.write(data)
        return data.size.toLong()
    }

    override fun domain(): String = "Exponent"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Exponent) return false
        if (group != other.group) return false
        if (isConstant != other.isConstant) return false
        if (!coefficients.zip(other.coefficients).all { (a,b) -> a == b }) return false
        return true
    }

    // MarshalBinary
    fun marshalBinary(): ByteArray {
        val rawExponent = RawExponentData(isConstant, coefficients)
        val data = Cbor.encodeToByteArray(rawExponent)

        val buffer = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN)

        buffer.putInt(data.size)

        val bytes = buffer.array()
        return bytes + data
    }

    fun unmarshalBinary(data: ByteArray) {
        // Read the size of the CBOR-encoded data
        val byteBuffer = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)
        val size = byteBuffer.int

        // Extract the CBOR-encoded data
        val cborData = ByteArray(size)
        byteBuffer.get(cborData)

        // Decode the CBOR data
        val rawExponent = Cbor.decodeFromByteArray<RawExponentData>(cborData)

        // Initialize the Exponent with the decoded data
        isConstant = rawExponent.isConstant
        coefficients = rawExponent.coefficients
    }


}