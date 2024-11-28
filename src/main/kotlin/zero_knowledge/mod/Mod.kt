package perun_network.ecdsa_threshold.zero_knowledge.mod

import perun_network.ecdsa_threshold.math.jacobi
import perun_network.ecdsa_threshold.math.sampleQuadraticNonResidue
import perun_network.ecdsa_threshold.zero_knowledge.prm.PROOF_NUM
import perun_network.ecdsa_threshold.zero_knowledge.prm.PrmPrivate
import perun_network.ecdsa_threshold.zero_knowledge.prm.PrmPublic
import java.math.BigInteger
import java.security.MessageDigest

/**
 * Public parameters of the Paillier-Blum Modulus Proof (Πmod).
 *
 * @property n The modulus N = pq
 */
data class ModPublic (
    val n : BigInteger,
)

/**
 * Data structure representing the private input of the prover for the Paillier-Blum Modulus Proof (Πmod)..
 * @property p Prime factor of N
 * @property q Prime factor of N
 * @property phi Euler's totient φ(N) = (p-1)(q-1)
 */
data class ModPrivate(
    val p: BigInteger,
    val q: BigInteger,
    val phi: BigInteger // φ(N) = (p-1)(q-1)
)


/**
 * Data structure representing a single proof commitment.
 * @property a Boolean flag indicating multiplication by -1
 * @property b Boolean flag indicating multiplication by w
 * @property x Quartic root of the transformed challenge value y'
 * @property z N-th root of the challenge value y
 */
data class ModCommitment(
    val a: Boolean,
    val b: Boolean,
    val x: BigInteger,
    val z: BigInteger
) {
    /**
     * Verifies the correctness of this commitment.
     * @param n Modulus N
     * @param w Random quadratic non-residue with Jacobi symbol -1
     * @param y Challenge value
     * @return true if the commitment satisfies the verification conditions
     */
    internal fun verify(n: BigInteger, w: BigInteger, y: BigInteger) : Boolean {
        val lhsZ = z.modPow(n, n) // lhs = zⁿ mod n
        if (lhsZ != y) {
            return false
        }

        val lhsX = x.modPow(BigInteger.valueOf(4), n) // lhs = x⁴ mod n

        // rhs = (-1)ᵃ * wᵇ * y mod n
        var rhs = y
        if (a) rhs = rhs.negate().mod(n)
        if (b) rhs = rhs.multiply(w).mod(n)

        val result = lhsX == rhs
        return result
    }
}


/**
 * Data structure representing a complete ZK proof.
 * @property w Random quadratic non-residue with Jacobi symbol -1
 * @property responses List of commitments for each challenge
 */
data class ModProof(
    val w: BigInteger,
    val responses: List<ModCommitment>
) {
    /**
     * Verifies the ZK proof.
     * @param id Unique identifier for the proof
     * @param rid Random identifier for the proof
     * @param public Public parameters containing the modulus N
     * @return true if all commitments are valid
     */
    internal fun verify(id: Int, rid:ByteArray, public: ModPublic) : Boolean {
        val n = public.n

        // Check if (w/n) = -1
        if (jacobi(w, n) != -1) {
            return false
        }

        // Generate challenges [yᵢ]
        val ys = challenge(id, rid, n, w)

        // Verify each response in parallel
        return responses.zip(ys).all { (response, y) -> response.verify(n, w, y) }
    }


    companion object {
        /**
         * Constructs a new ZK proof.
         * @param id Unique identifier for the proof
         * @param rid Random identifier for the proof
         * @param public Public parameters containing the modulus N
         * @param private Prover's private input (p, q, φ(N))
         * @return Constructed ModProof instance
         */
        internal fun newProof(id: Int, rid: ByteArray, public: ModPublic, private: ModPrivate): ModProof {
            val n = public.n
            val p = private.p
            val q = private.q
            val phi = private.phi

            val pHalf = (p - BigInteger.ONE) / BigInteger.TWO
            val qHalf = (q - BigInteger.ONE) / BigInteger.TWO

            val w = sampleQuadraticNonResidue(public.n)

            val nInverse = n.modInverse(phi) // N⁻¹ mod φ(N)
            val e = fourthRootExponent(phi) // Fourth root exponent

            // Generate challenges [yᵢ]
            val ys = challenge(id, rid, n, w)

            val commitments = mutableListOf<ModCommitment>()
            ys.forEach { y ->
                // Compute Z = yⁿ⁻¹ mod n
                val z = y.modPow(nInverse, n)

                // Make y' a quadratic residue
                val (a, b, yPrime) = makeQuadraticResidue(y, w, pHalf, qHalf, n, p, q)

                // Compute X = y'^¼
                val x = yPrime.modPow(e, n)

                // Add response
                commitments.add(ModCommitment(a, b, x, z))
            }

            return ModProof(w, commitments)
        }
    }
}

/**
 * Computes whether y is a quadratic residue modulo p and q.
 */
private fun isQRModPQ(y: BigInteger, pHalf: BigInteger, qHalf: BigInteger, p: BigInteger, q: BigInteger): Boolean {
    val one = BigInteger.ONE

    val pCheck = y.modPow(pHalf, p) == one
    val qCheck = y.modPow(qHalf, q) == one

    return pCheck && qCheck
}

/**
 * Computes the fourth root exponent (φ(N) + 4) / 8 squared.
 */
internal fun fourthRootExponent(phi: BigInteger): BigInteger {
    val four = BigInteger.valueOf(4)
    val ePrime = phi.add(four).shiftRight(3) // e' = (φ + 4) / 8
    return ePrime.pow(2) // e = (e')²
}

/**
 * Converts y into a quadratic residue if necessary.
 */
internal fun makeQuadraticResidue(
    y: BigInteger, w: BigInteger, pHalf: BigInteger, qHalf: BigInteger, n: BigInteger, p: BigInteger, q: BigInteger
): Triple<Boolean, Boolean, BigInteger> {
    var out = y.mod(n)
    var a = false
    var b = false

    if (isQRModPQ(out, pHalf, qHalf, p, q)) return Triple(a, b, out)

    // Multiply by -1
    out = out.negate().mod(n)
    a = true
    if (isQRModPQ(out, pHalf, qHalf, p, q)) return Triple(a, b, out)

    // Multiply by w
    out = out.multiply(w).mod(n)
    b = true
    if (isQRModPQ(out, pHalf, qHalf, p, q)) return Triple(a, b, out)

    // Multiply by -1 again
    out = out.negate().mod(n)
    a = false
    return Triple(a, b, out)
}

/**
 * Generates challenge values [yᵢ].
 * @param id Proof identifier
 * @param rid Random identifier
 * @param n Modulus N
 * @param w Random quadratic non-residue with Jacobi symbol -1
 * @return List of challenge values
 */
private fun challenge(id: Int, rid: ByteArray, n: BigInteger, w: BigInteger): List<BigInteger> {
    // Initialize a MessageDigest for SHA-256
    val digest = MessageDigest.getInstance("SHA-256")

    digest.update(id.toByte())
    digest.update(rid)
    digest.update(n.toByteArray())
    digest.update(w.toByteArray())


    val tmpBytes = digest.digest()

    return List(PROOF_NUM) {
        // Update the digest for each iteration
        digest.update(tmpBytes)
        val newDigest = digest.digest()
        BigInteger(1, newDigest)
    }
}