package perun_network.ecdsa_threshold.math.polynomial

import perun_network.ecdsa_threshold.math.curve.Curve
import perun_network.ecdsa_threshold.math.curve.Scalar
import perun_network.ecdsa_threshold.party.ID
import java.math.BigInteger


// lagrangeCoefficient returns the Lagrange coefficients at 0 for all parties in the interpolation domain.
fun lagrangeCoefficient(group: Curve, interpolationDomain: List<ID>): Map<ID, Scalar> {
    return lagrangeFor(group, interpolationDomain, interpolationDomain)
}

// LagrangeFor returns the Lagrange coefficients at 0 for all parties in the given subset.
fun lagrangeFor(group: Curve, interpolationDomain: List<ID>, subset: List<ID>): Map<ID, Scalar> {
    // numerator = x₀ * … * xₖ
    val (scalars, numerator) = getScalarsAndNumerator(group, interpolationDomain)
    val coefficients = mutableMapOf<ID, Scalar>()
    subset.forEach { j ->
        coefficients[j] = lagrange(group, scalars, numerator, j)
    }
    return coefficients
}

fun lagrangeSingle(curve: Curve, interpolationDomain: List<ID>, j: ID): Scalar {
    return lagrangeFor(curve, interpolationDomain, listOf(j))[j]!!
}

private fun getScalarsAndNumerator(curve: Curve, interpolationDomain: List<ID>): Pair<Map<ID, Scalar>, Scalar> {
    var numerator = curve.newScalar().setNat(BigInteger.ONE)
    val scalars = mutableMapOf<ID, Scalar>()
    interpolationDomain.forEach { id ->
        val xi = id.scalar(curve)
        scalars[id] = xi
        numerator = numerator.mul(xi)
    }
    return Pair(scalars, numerator)
}

// lagrange returns the Lagrange coefficient lⱼ(0), for j in the interpolation domain.
// The numerator is provided beforehand for efficiency reasons.
//
// The following formulas are taken from
// https://en.wikipedia.org/wiki/Lagrange_polynomial
//
//	x₀ ⋅⋅⋅ xₖ
//
// lⱼ(0) =	--------------------------------------------------
//
//	xⱼ⋅(x₀ - xⱼ)⋅⋅⋅(xⱼ₋₁ - xⱼ)⋅(xⱼ₊₁ - xⱼ)⋅⋅⋅(xₖ - xⱼ).
fun lagrange(curve: Curve, interpolationDomain: Map<ID, Scalar>, numerator: Scalar, j: ID): Scalar {
    val xJ = interpolationDomain[j]!!
    var tmp = curve.newScalar()

    // denominator = xⱼ * Π(xⱼ - xᵢ) for i ≠ j
    var denominator = curve.newScalar().setNat(BigInteger.ONE)
    interpolationDomain.forEach { (i, xI) ->
        if (i == j) {
            denominator = denominator.mul(xJ)
        } else {
            tmp = tmp.set(xJ).negate().add(xI)
            denominator = denominator.mul(tmp)
        }
    }

    // lⱼ = numerator / denominator
    var lJ = denominator.invert()
    lJ = lJ.mul(numerator)
    return lJ
}