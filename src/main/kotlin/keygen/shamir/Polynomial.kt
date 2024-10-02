package perun_network.ecdsa_threshold.keygen.shamir

import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.keygen.shamir.Polynomial.Companion.newPolynomial
import perun_network.ecdsa_threshold.math.sampleScalar
import java.math.BigInteger

// Polynomial represents f(X) = a₀ + a₁⋅X + … + aₜ⋅Xᵗ.
class Polynomial (
    val coefficients : List<Scalar>
) {
    companion object {
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

    fun eval(x : Scalar) : Scalar {
        if (x.isZero()) {
            throw IllegalArgumentException("Attempting to leak secret")
        }

        var result = Scalar.zero()
        for (i in coefficients.size - 1 downTo 0) {
            result = result.multiply(x).add(coefficients[i])
        }
        return result
    }
}



fun sampleEcdsaShare(threshold: Int, ids: List<Int>) : Pair<Map<Int, Scalar>, Map<Int, Point>> {
    val secretShares = mutableMapOf<Int, Scalar>() // x_i
    val publicShares = mutableMapOf<Int, Point>() // X_i
    val polynomial = newPolynomial(threshold)
    for (i in ids) {
        secretShares[i] = (polynomial.eval(Scalar(BigInteger.valueOf(i.toLong()))))
        publicShares[i] = (secretShares[i]!!.actOnBase())
    }

    return secretShares to publicShares
}