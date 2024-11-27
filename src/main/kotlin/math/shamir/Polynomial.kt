package perun_network.ecdsa_threshold.math.shamir

import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.math.shamir.Polynomial.Companion.newPolynomial
import perun_network.ecdsa_threshold.math.sampleScalar
import java.math.BigInteger

/**
 * Polynomial represents a function f(X) = a₀ + a₁⋅X + … + aₜ⋅Xᵗ.
 * This is used for secret sharing where coefficients represent secrets.
 * The coefficients are sampled using SecureRandom, so it can be used for Key Generation.
 *
 * @property coefficients The list of coefficients representing the polynomial.
 */
class Polynomial (
    private val coefficients : List<Scalar>
) {
    companion object {
        /**
         * Creates a new random polynomial of a given degree.
         *
         * @param degree The degree of the polynomial.
         * @return A polynomial with randomly sampled coefficients.
         */
        fun newPolynomial(degree: Int) : Polynomial {
            val coefficients = mutableListOf<Scalar>()

            // sample a0
            val constant = sampleScalar()
            coefficients.add(constant)

            for (i in 1..degree) {
                coefficients.add(sampleScalar())
            }
            return Polynomial(coefficients)
        }
    }

    /**
     * Evaluates the polynomial for a given scalar value `x`.
     *
     * @param x The scalar value at which to evaluate the polynomial.
     * @return The scalar result of the polynomial evaluation.
     * @throws IllegalArgumentException if `x` is zero (could leak the secret).
     */
    fun eval(x : Scalar) : Scalar {
        var result = Scalar.zero()
        for (i in coefficients.size - 1 downTo 0) {
            result = result.multiply(x).add(coefficients[i])
        }
        return result
    }
}

