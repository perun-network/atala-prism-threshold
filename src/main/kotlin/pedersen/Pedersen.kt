package perun_network.ecdsa_threshold.pedersen

import perun_network.ecdsa_threshold.math.isValidBigModN
import java.math.BigInteger

data class PedersenParameters(
    val n: BigInteger, // Modulus
    val s: BigInteger,
    val t: BigInteger,
) {
    // Commit computes sˣ tʸ (mod N)
    fun commit(x: BigInteger, y: BigInteger): BigInteger {
        val sx = s.modPow(x, n)
        val ty = t.modPow(y, n)

        return sx.multiply(ty).mod(n)
    }

    // Verify returns true if sᵃ tᵇ ≡ S Tᵉ (mod N).
    fun verify(a: BigInteger, b: BigInteger, e: BigInteger, S: BigInteger, T: BigInteger): Boolean {
        if (!isValidBigModN(n, S, T)) {
            return false
        }

        val sa = s.modPow(a, n)
        val tb = t.modPow(b, n)
        val lhs = sa.multiply(tb).mod(n) // lhs = sᵃ⋅tᵇ (mod N)

        val te = T.modPow(e, n) // Tᵉ (mod N)
        val rhs = te.multiply(S).mod(n) // rhs = S⋅Tᵉ (mod N)
        return lhs == rhs
    }
}