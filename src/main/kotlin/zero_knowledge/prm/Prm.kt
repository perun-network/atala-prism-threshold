package perun_network.ecdsa_threshold.zero_knowledge.prm

import perun_network.ecdsa_threshold.math.isValidModN
import perun_network.ecdsa_threshold.math.sampleModN
import perun_network.ecdsa_threshold.pedersen.PedersenParameters
import java.math.BigInteger
import java.security.MessageDigest

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
        val (eList, exc) = challenge(id, public, As)
        if (exc != null) throw exc

        val n = public.aux.n
        val s = public.aux.s
        val t = public.aux.t

        val one = BigInteger.ONE
        for (i in 0..PROOF_NUM-1) {
            var rhs = BigInteger.ZERO
            val z = Zs[i]
            val a = As[i]

            // Check if `a` and `z` are valid under modulus `n`
            if (!isValidModN(n, a, z)) {
                return false
            }

            // Check if `a` is not equal to 1
            if (a == one) {
                return false
            }

            val lhs = t.modPow(z, n)

            // Conditional multiplication
            if (eList[i]) {
                rhs = (a.multiply(s)).mod(n)
            } else {
                rhs = a
            }

            // Compare lhs and rhs
            if (lhs != rhs) {
                return false
            }
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

            val (eList, exc) = challenge(id, public, AList)
            if (exc != null) {
                throw exc
            }

            for (i in 0..PROOF_NUM-1) {
                var z = aList[i]


                if (eList[i]) {
                    z = (z.add(private.lambda)).mod(private.phi)
                }

                ZList.add(z)
            }

            return PrmProof(AList, ZList)
        }
    }
}

private fun challenge(
    id: Int,
    public: PrmPublic,
    A: List<BigInteger>
): Pair<List<Boolean>, Exception?> {
    return try {
        // Initialize the MessageDigest for SHA-256
        val digest = MessageDigest.getInstance("SHA-256")

        digest.update(id.toByte())

        // Update the digest with the public auxiliary components
        digest.update(public.aux.n.toByteArray())
        digest.update(public.aux.s.toByteArray())
        digest.update(public.aux.t.toByteArray())

        // Update the digest with each element in A
        A.forEach { element ->
            digest.update(element.toByteArray())
        }

        // Generate the hash digest
        val tmpBytes = digest.digest()

        // Create a list of booleans based on the hash digest
        val es = List(PROOF_NUM) { i ->
            (tmpBytes[i % tmpBytes.size].toInt() and 1) == 1
        }

        // Return the list of booleans and no error
        Pair(es, null)
    } catch (e: Exception) {
        // Return an empty list and the exception if something goes wrong
        Pair(emptyList(), e)
    }
}


