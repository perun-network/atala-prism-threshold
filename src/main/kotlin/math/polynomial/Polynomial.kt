package perun_network.ecdsa_threshold.math.polynomial

import perun_network.ecdsa_threshold.math.curve.*
import perun_network.ecdsa_threshold.math.sample.SecureRandomInputStream
import perun_network.ecdsa_threshold.math.sample.scalar
import java.security.SecureRandom

class Polynomial(
    val group: Curve,
    val coefficients: List<Scalar>,
) {
    companion object {
        // Generates a new polynomial with a given degree and constant.
        fun newPolynomial(group: Curve, degree: Int, constant: Scalar?): Polynomial {
            val coefficients = mutableListOf<Scalar>()
            val adjustedConstant = constant ?: group.newScalar()
            coefficients.add(adjustedConstant)

            for (i in 1..degree) {
                coefficients.add(scalar(SecureRandomInputStream(SecureRandom()) ,group))
            }

            return Polynomial(group, coefficients)
        }
    }

    // Evaluates the polynomial at a given index using Horner's method.
    fun evaluate(index: Scalar): Scalar {
        if (index.isZero()) {
            throw IllegalArgumentException("Attempt to leak secret")
        }

        var result = group.newScalar()
        for (i in coefficients.indices.reversed()) {
            result = result.mul(index).add(coefficients[i])
        }
        return result
    }

    // Returns the constant coefficient of the polynomial.
    fun constant(): Scalar {
        return group.newScalar().set(coefficients[0])
    }

    // Returns the degree of the polynomial.
    fun degree(): Int {
        return coefficients.size - 1
    }
}


