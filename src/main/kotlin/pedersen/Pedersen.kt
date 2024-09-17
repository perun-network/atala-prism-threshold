package perun_network.ecdsa_threshold.pedersen

import perun_network.ecdsa_threshold.math.isValidBigModN
import java.math.BigInteger

sealed class PedersenError(override val message: String) : Exception(message) {
    object NullFields: PedersenError("contains null field")
    object SEqualT : PedersenError("S cannot be equal to T")
    object NotValidModN : PedersenError("S and T must be in [1,…,N-1] and coprime to N")
}

data class PedersenParameters(
    val n: BigInteger, // Modulus
    val s: BigInteger,
    val t: BigInteger,
) {

    companion object {
        // ValidateParameters checks n, s, and t, and returns an error if any of the following is true:
        // - n, s, or t is null.
        // - s, t are not in [1, …,n-1].
        // - s, t are not coprime to N.
        // - s = t.
        fun validateParameters(n: BigInteger?, s: BigInteger?, t: BigInteger?): PedersenError? {
            if (n == null || s == null || t == null) {
                return PedersenError.NullFields
            }
            // s, t ∈ ℤₙˣ
            if (!isValidBigModN(n, s, t)) {
                return PedersenError.NotValidModN
            }
            // s ≡ t
            if (s.compareTo(t) == 0) {
                return PedersenError.SEqualT
            }
            return null
        }
    }

    // N = p•q, p ≡ q ≡ 3 mod 4.
    fun n(): BigInteger = n

    // S = r² mod N.
    fun s(): BigInteger = s

    // T = Sˡ mod N.
    fun t(): BigInteger = t

    // Commit computes sˣ tʸ (mod N)
    //
    // x and y are taken as Int, because we want to keep these values in secret,
    // in general. The commitment produced, on the other hand, hides their values,
    // and can be safely shared.
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