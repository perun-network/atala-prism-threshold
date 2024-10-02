package perun_network.ecdsa_threshold.math

import java.math.BigInteger

// IsValidBigModN checks that ints are all in the range [1,…,N-1] and are co-prime to N.
fun isValidBigModN(N: BigInteger, vararg ints: BigInteger?): Boolean {
    val one = BigInteger.ONE
    for (i in ints) {
        if (i == null) {
            return false
        }
        if (i.signum() != 1) {
            return false
        }
        if (i >= N) {
            return false
        }
        val gcd = i.gcd(N)
        if (gcd != one) {
            return false
        }
    }
    return true
}

// IsInIntervalLEps returns true if n ∈ [-2ˡ⁺ᵉ,…,2ˡ⁺ᵉ].
fun isInIntervalLEps(n: BigInteger): Boolean {
    return n.bitLength() <= LPlusEpsilon
}

// IsInIntervalLPrimeEps returns true if n ∈ [-2ˡ'⁺ᵉ,…,2ˡ'⁺ᵉ].
fun isInIntervalLPrimeEps(n: BigInteger): Boolean {
    return n.bitLength() <= LPrimePlusEpsilon
}
