package perun_network.ecdsa_threshold.zero_knowledge

import perun_network.ecdsa_threshold.math.isValidModN
import perun_network.ecdsa_threshold.math.sampleModN
import perun_network.ecdsa_threshold.math.sampleModNStar
import perun_network.ecdsa_threshold.pedersen.PedersenParameters
import java.math.BigInteger
import java.security.MessageDigest

/**
 * [PROOF_NUM] is the standard numbers of challenges and proofs.
 */
const val PROOF_NUM = 80

/**
 * Represents the public parameters of the Pedersen Parameters ZK proof (Πprm).
 *
 * @property aux The Pedersen parameters including modulus `n`, base `s`, and generator `t`.
 */
data class PrmPublic (
    val aux : PedersenParameters,
)

/**
 * Represents the private parameters of the Pedersen Parameters ZK proof (Πprm).
 *
 * @property phi Euler's totient function value φ(N), used for sampling random elements in Zφ(N).
 * @property lambda The secret exponent λ such that s = t^λ mod N.
 */
data class PrmPrivate (
    val phi: BigInteger,
    val lambda : BigInteger
)

/**
 * Represents the zero-knowledge proof for Pedersen parameters (Πprm).
 *
 * @property As List of commitments `A_i = t^a_i mod N` sent to the verifier.
 * @property Zs List of responses `z_i = a_i + e_i * λ mod φ(N)` from the prover.
 */
data class PrmProof (
    val As : List<BigInteger>,
    val Zs: List<BigInteger>
) {
    /**
     * Verifies the proof against the public parameters.
     *
     * @param id The unique identifier for the proof session.
     * @param public The public parameters used in the protocol.
     * @return `true` if the proof is valid, otherwise `false`.
     * @throws Exception If the challenge generation encounters an error.
     */
    fun verify(id: Int, public: PrmPublic) : Boolean {
        val (eList, exc) = challenge(id, public, As)
        if (exc != null) throw exc

        val n = public.aux.n
        val s = public.aux.s
        val t = public.aux.t

        val one = BigInteger.ONE

        for (i in 0..PROOF_NUM-1) {
            var rhs: BigInteger
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
        /**
         * Generates a new zero-knowledge proof for the given public and private parameters.
         *
         * @param id The unique identifier for the proof session.
         * @param public The public parameters used in the protocol.
         * @param private The private parameters (secret inputs) of the prover.
         * @return A valid instance of [PrmProof].
         * @throws Exception If the challenge generation encounters an error.
         */
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

/**
 * Generates the challenge values (e_i) for the proof, based on a hash function.
 *
 * @param id The unique identifier for the proof session.
 * @param public The public parameters used in the protocol.
 * @param A List of commitments sent by the prover.
 * @return A pair consisting of the list of challenge bits and an optional exception.
 */
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