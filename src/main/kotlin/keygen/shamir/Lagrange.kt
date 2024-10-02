package perun_network.ecdsa_threshold.keygen.shamir

import perun_network.ecdsa_threshold.ecdsa.Scalar
import java.math.BigInteger

fun lagrange(signers : List<Int>) : Map<Int, Scalar> {
    val coefficients = mutableMapOf<Int, Scalar>()
    for (signer in signers) {
        coefficients[signer] = lagrangeOf(signer, signers)
    }
    return coefficients
}

// Calculate Lagrange coefficients for a list of shares.
fun lagrangeOf(j : Int, signers: List<Int>) : Scalar {
    var result = Scalar(BigInteger.ONE)
    val x_j = Scalar.scalarFromInt(j)

    // denominator
    for (i  in signers) {
        if (i != j) {
            val x_i = Scalar.scalarFromInt(i)
            val denominator = x_i.subtract(x_j) // x_m - x_j
            result = result.multiply(x_i).multiply(denominator.invert())
        }
    }
    return result
}