package perun_network.ecdsa_threshold.math.shamir

import perun_network.ecdsa_threshold.ecdsa.Scalar
import java.math.BigInteger

/**
 * Computes Lagrange interpolation coefficients for a list of signers.
 *
 * @param signers A list of signer IDs.
 * @return A map where the keys are the signer IDs and the values are their corresponding Lagrange coefficients.
 */
fun lagrange(signers : List<Int>) : Map<Int, Scalar> {
    val coefficients = mutableMapOf<Int, Scalar>()
    for (signer in signers) {
        coefficients[signer] = lagrangeOf(signer, signers)
    }
    return coefficients
}

/**
 * Calculates the Lagrange coefficient for a specific signer.
 *
 * @param j The ID of the signer whose coefficient is being calculated.
 * @param signers A list of signer IDs.
 * @return The Lagrange coefficient for signer `j`.
 */
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