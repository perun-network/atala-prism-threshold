package perun_network.ecdsa_threshold.zero_knowledge.prm

import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.ecdsa.secp256k1Order
import perun_network.ecdsa_threshold.math.isValidModN
import perun_network.ecdsa_threshold.math.sampleModN
import perun_network.ecdsa_threshold.math.sampleModNStar
import perun_network.ecdsa_threshold.pedersen.PedersenParameters
import perun_network.ecdsa_threshold.zero_knowledge.sch.SchnorrPublic
import java.math.BigInteger
import java.security.MessageDigest
import kotlin.experimental.and

/**
 * [PROOF_NUM] is the standard numbers of challenges and proofs.
 */
const val PROOF_NUM = 80

data class PrmPublic (
    val aux : PedersenParameters,
)

data class PrmPrivate (
    val phi: BigInteger,
    val lambda : BigInteger
)

data class PrmProof (
    val As : List<BigInteger>,
    val Zs: List<BigInteger>
) {
    fun verify(id: Int, public: PrmPublic) : Boolean {
        val eList = challenge(id, public, As)

        val n = public.aux.n
        val s = public.aux.s
        val t = public.aux.t

        val one = BigInteger.ONE
        for (i in 0..PROOF_NUM-1) {
            var rhs = BigInteger.ZERO
            val z = Zs[i]
            val a = As[i]

            // Check if `a` and `z` are valid under modulus `n`
            if (!isValidModN(n, a, z)) return false

            // Check if `a` is not equal to 1
            if (a == one) return false

            val lhs = t.modPow(z, n)

            // Conditional multiplication
            if (eList[i]) {
                rhs = a.multiply(s).mod(n)
            } else {
                rhs = a
            }

            // Compare lhs and rhs
            if (lhs != rhs) return false
        }

        return true
    }

    companion object {
        internal fun newProof(id: Int, public: PrmPublic, private: PrmPrivate) : PrmProof {
            val aList = mutableListOf<BigInteger>()
            val AList = mutableListOf<BigInteger>()
            val ZList = mutableListOf<BigInteger>()

            for (i in 0..PROOF_NUM-1) {
                val a = sampleModN(private.phi)
                val A = public.aux.t.modPow(a, public.aux.n)

                aList.add(a)
                AList.add(A)
            }

            val eList = challenge(id, public, AList)

            for (i in 0..PROOF_NUM-1) {
                var z = aList[i]


                if (eList[i]) {
                    z = z.add(private.lambda).mod(private.phi)
                }

                ZList.add(z)
            }

            return PrmProof(AList, ZList)
        }
    }
}

private fun challenge(id: Int, public: PrmPublic, aList: List<BigInteger>): List<Boolean> {
    val eList = mutableListOf<Boolean>()

    // Initialize a MessageDigest for SHA-256
    val digest = MessageDigest.getInstance("SHA-256")

    digest.update(id.toByte())
    digest.update(public.aux.n.toByteArray())
    digest.update(public.aux.s.toByteArray())
    digest.update(public.aux.t.toByteArray())
    digest.update(aList.size.toByte())

    for (i in 0..PROOF_NUM-1) {
        digest.update(aList[i].toByteArray())
    }

    val tmpBytes = digest.digest()

    val es = List(PROOF_NUM) { i -> (tmpBytes[i] and 1).toInt() == 1 }

    return es
}

