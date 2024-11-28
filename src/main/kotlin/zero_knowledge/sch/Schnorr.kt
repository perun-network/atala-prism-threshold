package perun_network.ecdsa_threshold.zero_knowledge.sch

import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.ecdsa.secp256k1Order
import perun_network.ecdsa_threshold.math.sampleScalar
import java.math.BigInteger

/**
 * Represents the public parameters of the Schnorr proof (Πsch).
 *
 * @property X The public key, computed as X = g^x, where g is the base point of the group and x is the secret key.
 */
data class SchnorrPublic (
    val X : Point,
)

/**
 * Represents the private parameters of the Schnorr proof (Πsch).
 *
 * @property x The secret key, such that X = g^x.
 */
data class SchnorrPrivate (
    val x : Scalar
)

/**
 * Represents a commitment in the Schnorr protocol (Πsch).
 *
 * @property alpha A random scalar used for generating the commitment.
 * @property A The commitment point, computed as A = g^alpha.
 */
data class SchnorrCommitment(
    val alpha: Scalar,
    val A: Point,
) {
    companion object {
        /**
         * Generates a new random commitment for the Schnorr proof (Πsch).
         *
         * @return A new [SchnorrCommitment] containing a random scalar and its corresponding point.
         */
        internal fun newCommitment() : SchnorrCommitment {
            val alpha = sampleScalar()
            return SchnorrCommitment(alpha, alpha.actOnBase())
        }
    }
}

/**
 * Represents the proof in the Schnorr Zero Knowledge protocol (Πsch).
 *
 * @property z The proof scalar, computed as z = alpha + ex mod q.
 * @property A The commitment point used in the proof.
 */
data class SchnorrProof(
    val z: Scalar,
    val A: Point,
) {
    /**
     * Validates the structure of the proof.
     *
     * @return `true` if the proof is structurally valid, `false` otherwise.
     */
    private fun isValid(): Boolean {
        if (z.isZero() || A.isIdentity()) {
            return false
        }
        return true
    }

    /**
     * Verifies the Schnorr proof against the public parameters and commitment.
     *
     * @param id A unique identifier for the proof session.
     * @param rid A random session identifier as a byte array.
     * @param public The public parameters of the Schnorr proof.
     * @return `true` if the proof is valid, otherwise `false`.
     */
    fun verify(id: Int, rid: ByteArray, public: SchnorrPublic) : Boolean {
        if (!isValid()) return false

        val e = challenge(id, rid, public, A)

        // Check g^z = A · X^e
        if (z.actOnBase() != Scalar.scalarFromBigInteger(e).act(public.X).add(A)) {
            return false
        }

        return true
    }

    companion object {
        /**
         * Generates a new Schnorr proof for the given inputs.
         *
         * @param id A unique identifier for the proof session.
         * @param rid A random session identifier as a byte array.
         * @param public The public parameters of the Schnorr proof.
         * @param private The private parameters (secret key) of the Schnorr proof.
         * @return A valid [SchnorrProof].
         */
        internal fun newProof(id: Int, rid: ByteArray, public: SchnorrPublic, private: SchnorrPrivate): SchnorrProof {
            val alpha = sampleScalar()

            val A = alpha.actOnBase()

            val e = challenge(id, rid, public, A)

            val z = alpha.add(private.x.multiply(Scalar.scalarFromBigInteger(e)))
            return SchnorrProof(z, A)
        }

        /**
         * Generates a Schnorr proof using a precomputed commitment.
         *
         * @param id A unique identifier for the proof session.
         * @param rid A random session identifier as a byte array.
         * @param public The public parameters of the Schnorr proof.
         * @param private The private parameters (secret key) of the Schnorr proof.
         * @param commitment A precomputed [SchnorrCommitment].
         * @return A valid [SchnorrProof].
         */
        internal fun newProofWithCommitment(id: Int, rid: ByteArray, public: SchnorrPublic, private: SchnorrPrivate, commitment: SchnorrCommitment): SchnorrProof {
            val e = challenge(id, rid, public, commitment.A)
            val z = commitment.alpha.add(private.x.multiply(Scalar.scalarFromBigInteger(e)))

            return SchnorrProof(z, commitment.A)
        }
    }
}

/**
 * Computes the challenge value for the Schnorr proof using the session parameters.
 *
 * @param id A unique identifier for the proof session.
 * @param rid A random session identifier as a byte array.
 * @param public The public parameters of the Schnorr proof.
 * @param A The commitment point from the prover.
 * @return A challenge value as a [BigInteger].
 */
private fun challenge(id: Int, rid: ByteArray, public: SchnorrPublic, A: Point): BigInteger {
    // Collect relevant parts to form the challenge
    val inputs = listOf<BigInteger>(
        public.X.x,
        public.X.y,
        A.x,
        A.y,
        BigInteger.valueOf(id.toLong()),
        BigInteger(rid)
    )
    return inputs.fold(BigInteger.ZERO) { acc, value -> acc.add(value).mod(secp256k1Order()) }.mod(
        secp256k1Order()
    )
}
