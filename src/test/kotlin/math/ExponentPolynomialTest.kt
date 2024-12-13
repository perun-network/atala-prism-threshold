package math

import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.ecdsa.newPoint
import perun_network.ecdsa_threshold.math.sampleScalar
import perun_network.ecdsa_threshold.math.shamir.Polynomial
import perun_network.ecdsa_threshold.math.shamir.sum
import kotlin.test.Test
import kotlin.test.assertEquals

class ExponentPolynomialTest {
    @Test
    fun testExponentEvaluate() {
        var lhs: Point
        for (x in 0 until 5) {
            val N = 1000
            val secret = if (x % 2 == 0) {
                sampleScalar()
            } else {
                Scalar.zero()
            }

            val poly = Polynomial.newPolynomial(N, secret)
            val polyExp = poly.exponentPolynomial()
            val randomIndex = sampleScalar()

            lhs = poly.eval(randomIndex).actOnBase()
            val rhs1 = polyExp.eval(randomIndex)

            assertEquals(lhs, rhs1, "Base eval differs from Horner method at iteration $x")
        }
    }

    @Test
    fun testSum() {
        val N = 20
        val Deg = 10
        val randomIndex = sampleScalar()

        // Compute f1(x) + f2(x) + …
        var evaluationScalar = Scalar.zero()

        // Compute F1(x) + F2(x) + …
        var evaluationPartial = newPoint()

        val polys = Array(N) { Polynomial.newPolynomial(Deg) }
        val polysExp = Array(N) { polys[it].exponentPolynomial() }

        for (i in polys.indices) {
            evaluationScalar = evaluationScalar.add(polys[i].eval(randomIndex))
            evaluationPartial = evaluationPartial.add(polysExp[i].eval(randomIndex))
        }

        // Compute (F1 + F2 + …)(x)
        val summedExp = sum(polysExp.toList())
        val evaluationSum = summedExp.eval(randomIndex)

        val evaluationFromScalar = evaluationScalar.actOnBase()
        assertEquals(evaluationSum, evaluationFromScalar, "Summed exponent does not match evaluation from scalar.")
        assertEquals(evaluationSum, evaluationPartial, "Summed exponent does not match partial evaluation.")
    }
}