package perun_network.ecdsa_threshold.math.shamir

import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.ecdsa.newPoint

/**
 * Represents a polynomial over points on an elliptic curve.
 * The polynomial has the form:
 *   f(X) = P₀ + P₁⋅X + P₂⋅X² + ... + Pₜ⋅Xᵗ
 * where Pᵢ are points on the elliptic curve, and X is a scalar.
 *
 * @property isConstant Indicates if the polynomial represents a constant value.
 * @property coefficients List of elliptic curve points representing the coefficients.
 */
class ExponentPolynomial (
    val isConstant: Boolean,
    val coefficients: List<Point>
) {
    /**
     * Evaluates the polynomial at a given scalar `x` using Horner's method.
     *
     * @param x The scalar at which to evaluate the polynomial.
     * @return The result as a Point on the elliptic curve.
     */
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

    /**
     * Provides a clone of this exponent polynomial.
     *
     * @return A cloned ExponentPolynomial based on this Exponent Polynomial.
     */
    fun clone() : ExponentPolynomial {
        return ExponentPolynomial(isConstant, coefficients.toMutableList())
    }

    /**
     * Adds this polynomial to another polynomial.
     *
     * @param other The ExponentPolynomial to add.
     * @return A new ExponentPolynomial representing the sum.
     * @throws IllegalArgumentException If the two polynomials have different lengths
     *                                  or different `isConstant` flags.
     */
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

    /**
     * Serializes the polynomial to a byte array.
     *
     * @return The serialized byte array representation.
     */
    fun toByteArray(): ByteArray {
        // Convert the `isConstant` boolean to a byte (1 for true, 0 for false)
        val constantByte = if (isConstant) 1.toByte() else 0.toByte()

        // Convert each `Point` in `coefficients` to its byte array
        val coefficientsBytes = coefficients.flatMap { it.toByteArray().asList() }

        // Combine the `isConstant` byte with the serialized coefficients
        return byteArrayOf(constantByte) + coefficientsBytes.toByteArray()
    }
}

/**
 * Computes the sum of a list of ExponentPolynomial objects.
 *
 * @param ePolynoms The list of ExponentPolynomial objects.
 * @return The resulting sum as a single ExponentPolynomial.
 * @throws IllegalArgumentException If the input list is empty.
 */
fun sum(ePolynoms: List<ExponentPolynomial>) : ExponentPolynomial {
    var sum = ePolynoms[0].clone()

    for (i in 1 until ePolynoms.size) {
        sum = sum.add(ePolynoms[i])
    }

    return sum
}