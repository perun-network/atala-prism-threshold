package perun_network.ecdsa_threshold.zero_knowledge

import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.ecdsa.secp256k1Order
import perun_network.ecdsa_threshold.math.*
import java.math.BigInteger

/**
 * Public parameters for the Dlog with El-Gamal Commitment (elog) zero-knowledge proof.
 *
 * @property L Elliptic curve point representing G^λ.
 * @property M Elliptic curve point representing G^y * X^λ.
 * @property X ElGamal public key.
 * @property Y Elliptic curve point representing h^y.
 * @property h Base point for ElGamal encryption.
 */
data class ElogPublic (
    val L: Point, // L = G^lambda
    val M: Point, // M = G^y*X^lambda
    val X : Point, // El-Gamal Public
    val Y: Point, // Y = h^y
    val h: Point, // base for El-Gamal

)

/**
 * Private parameters for the Dlog with El-Gamal Commitment (elog) zero-knowledge proof.
 *
 * @property y Scalar representing a secret value used in the proof.
 * @property lambda Scalar representing a secret exponent.
 */
data class ElogPrivate(
    val y: Scalar,
    val lambda : Scalar
)

/**
 * Commitment values generated during the zero-knowledge proof.
 *
 * @property A Elliptic curve point representing G^α.
 * @property N Elliptic curve point representing G^m + X^α.
 * @property B Elliptic curve point representing h^m.
 */
data class ElogCommitment(
    val A : Point, // A = G^α
    val N : Point, // N = G^m+X^α
    val B : Point // B = h^m
)

/**
 * The zero-knowledge proof for the Dlog with El-Gamal Commitment (elog).
 *
 * @property commitment The commitments made during the proof.
 * @property z Scalar representing α + eλ (mod q).
 * @property u Scalar representing m + ey (mod q).
 */
data class ElogProof (
    val commitment : ElogCommitment,
    val z: Scalar, // z = α+eλ (mod q)
    val u: Scalar // u = m+ey (mod q)
) {
    /**
     * Validates the proof.
     *
     * @return True if the proof is valid, false otherwise.
     */
    private fun isValid(): Boolean {
        if (commitment.A.isIdentity() || commitment.N.isIdentity() || commitment.B.isIdentity()) {
            return false
        }

        return (!(z.isZero() || u.isZero()))
    }

    /**
     * Verifies the proof's integrity and correctness against public parameters.
     *
     * @param id The identifier for the session or proof.
     * @param public The public parameters used for verification.
     * @return True if the proof is verified, false otherwise.
     */
    fun verify(id: Int, public: ElogPublic): Boolean {
        if (!isValid()) return false

        val e = challenge(id, public, commitment)

        // G^z == A · L^e
        if (z.actOnBase() != commitment.A.add(Scalar.scalarFromBigInteger(e).act(public.L))) {
            return false
        }

        // G^u * X^z == N*M^e
        if (u.actOnBase().add(z.act(public.X)) != Scalar.scalarFromBigInteger(e).act(public.M).add(commitment.N)) {
            return false
        }

        // h^u == B*Y^e
        if (u.act(public.h) != commitment.B.add(Scalar.scalarFromBigInteger(e).act(public.Y))) {
            return false
        }
        return true
    }

    companion object {
        /**
         * Generates a challenge based on public parameters and the commitment.
         *
         * @param id The identifier for the session or proof.
         * @param public The public parameters.
         * @param commitment The commitment associated with the proof.
         * @return The generated challenge value.
         */
        private fun challenge(id: Int, public: ElogPublic, commitment: ElogCommitment): BigInteger {
            // Collect relevant parts to form the challenge
            val inputs = listOf<BigInteger>(
                public.X.x,
                public.X.y,
                public.L.x,
                public.L.y,
                public.M.x,
                public.M.y,
                public.Y.x,
                public.Y.y,
                public.h.x,
                public.h.y,
                commitment.A.x,
                commitment.A.y,
                commitment.N.x,
                commitment.N.y,
                commitment.B.x,
                commitment.B.y,
                BigInteger.valueOf(id.toLong())
            )
            return inputs.fold(BigInteger.ZERO) { acc, value -> acc.add(value).mod(secp256k1Order()) }.mod(
                secp256k1Order()
            )
        }

        /**
         * Creates a new proof based on public and private parameters.
         *
         * @param id The identifier for the session or proof.
         * @param public The public parameters for the proof.
         * @param private The private parameters for the proof.
         * @return The newly created proof.
         */
        fun newProof(id: Int, public: ElogPublic, private: ElogPrivate): ElogProof {

            val alpha = sampleScalar()
            val m = sampleScalar()

            val A = alpha.actOnBase() // A = G^α
            val N = m.actOnBase().add(alpha.act(public.X)) // N = G^m+X^α
            val B = m.act(public.h) // B = h^m

            val commitment = ElogCommitment(A, N, B)

            val e = challenge(id, public, commitment)

            val z = (private.lambda.multiply(Scalar.scalarFromBigInteger(e))).add(alpha) // z = α+eλ (mod q)
            val u = m.add(Scalar.scalarFromBigInteger(e).multiply(private.y)) // u = m+ey (mod q)
            return ElogProof(commitment, z, u)
        }
    }
}