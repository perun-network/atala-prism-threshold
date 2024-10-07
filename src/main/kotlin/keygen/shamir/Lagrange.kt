package perun_network.ecdsa_threshold.keygen.shamir

import perun_network.ecdsa_threshold.ecdsa.Scalar

fun lagrange(signers : List<Int>) : Map<Int, Scalar> {
    val coefficients = mutableMapOf<Int, Scalar>()
    var numerator = 1
    // numerator = (x_i - 0) for (i in signers)
    for (signer in signers) {
        numerator *= signer
    }

    for (signer in signers) {
        coefficients[signer] = lagrangeOf(signer, signers, numerator)
    }
    return coefficients
}

// Calculate Lagrange coefficients for a list of shares at point 0.
fun lagrangeOf(j : Int, signers: List<Int>, numerator: Int) : Scalar {
    val x_j = Scalar.scalarFromInt(j)
    var denominator = Scalar.scalarFromInt(1)
    for (i  in signers) {
        val x_i = Scalar.scalarFromInt(i)
        if (i == j) {
            denominator = denominator.multiply(x_j)
            continue
        }
        val diff = x_i.subtract(x_j)
        denominator = denominator.multiply(diff)
    }

    // lⱼ = numerator/denominator
    val result = (denominator.invert()).multiply(Scalar.scalarFromInt(numerator))
    return result
}