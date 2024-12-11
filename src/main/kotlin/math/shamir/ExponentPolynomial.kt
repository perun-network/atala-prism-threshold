package perun_network.ecdsa_threshold.math.shamir

import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.ecdsa.newPoint

class ExponentPolynomial (
    val isConstant: Boolean,
    val coefficients: List<Point>
) {
    fun eval(x : Scalar) : Point {
        var result = newPoint()

        // Iterate over coefficients in reverse order
        for (i in coefficients.size - 1 downTo 0) {
            result = x.act(result).add(coefficients[i])
        }

        if (isConstant) {
            // If constant, multiply result by x
            result = x.act(result)
        }

        return result
    }

    fun clone() : ExponentPolynomial {
        return ExponentPolynomial(isConstant, coefficients.toMutableList())
    }

    fun add(other: ExponentPolynomial) : ExponentPolynomial {
        if (this.coefficients.size != other.coefficients.size) {
            throw IllegalArgumentException("different length coefficients")
        }

        if (isConstant !=  other.isConstant) throw IllegalArgumentException("different constant flag")

        val newCoeffs = mutableListOf<Point>()

        for (i in coefficients.indices) {
            newCoeffs.add(this.coefficients[i].add(other.coefficients[i]))
        }

        return ExponentPolynomial(isConstant = isConstant, coefficients = newCoeffs)
    }

    fun toByteArray(): ByteArray {
        // Convert the `isConstant` boolean to a byte (1 for true, 0 for false)
        val constantByte = if (isConstant) 1.toByte() else 0.toByte()

        // Convert each `Point` in `coefficients` to its byte array
        val coefficientsBytes = coefficients.flatMap { it.toByteArray().asList() }

        // Combine the `isConstant` byte with the serialized coefficients
        return byteArrayOf(constantByte) + coefficientsBytes.toByteArray()
    }
}

fun sum(ePolynoms: List<ExponentPolynomial>) : ExponentPolynomial {
    var sum = ePolynoms[0].clone()

    for (i in 1 until ePolynoms.size) {
        sum = sum.add(ePolynoms[i])
    }

    return sum
}