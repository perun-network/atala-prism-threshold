package perun_network.ecdsa_threshold.zkproof.logstar

import perun_network.ecdsa_threshold.ecdsa.*
import perun_network.ecdsa_threshold.math.*
import perun_network.ecdsa_threshold.paillier.PaillierCipherText
import perun_network.ecdsa_threshold.paillier.PaillierPublic
import perun_network.ecdsa_threshold.pedersen.PedersenParameters
import java.math.BigInteger

/**
 * Represents the public parameters for the Log* zero-knowledge proof.
 *
 * @property C The ciphertext representing the encrypted value Enc₀(x; ρ).
 * @property X The point G raised to the power of x (X = G^x).
 * @property g The base point used for the proof.
 * @property n0 The Paillier public key used for encryption.
 * @property aux The Pedersen parameters used for commitment.
 */
data class LogStarPublic(
    val C : PaillierCipherText,
    val X : Point,
    val g: Point,
    val n0 : PaillierPublic,
    val aux    : PedersenParameters
)

/**
 * Represents the private parameters for the Log* zero-knowledge proof.
 *
 * @property x The private key component.
 * @property rho The nonce used to encrypt C.
 */
data class LogStarPrivate(
    val x: BigInteger,
    val rho : BigInteger
)

/**
 * Represents the commitment values used in the Log* zero-knowledge proof.
 *
 * @property S The value calculated as S = sˣ tᵘ (mod N).
 * @property A The ciphertext calculated from the first private parameter.
 * @property Y The point calculated as Y = G^a.
 * @property D The value calculated as D = sᵃ tᵍ (mod N).
 */
data class LogStarCommitment(
    val S: BigInteger,
    val A: PaillierCipherText,
    val Y: Point,
    val D: BigInteger
)

/**
 * Represents the proof in the Log* zero-knowledge protocol.
 *
 * @property commitment The commitment associated with this proof.
 * @property z1 The value calculated as z₁ = α + e⋅x.
 * @property z2 The value calculated as z₂ = r⋅ρᵉ (mod N).
 * @property z3 The value calculated as z₃ = γ + e⋅μ.
 */
class LogStarProof(
    private val commitment: LogStarCommitment,
    private val z1: BigInteger,
    private val z2: BigInteger,
    private val z3: BigInteger
) {
    /**
     * Validates the proof against the provided public parameters.
     *
     * @param public The public parameters against which to validate the proof.
     * @return True if the proof is valid, false otherwise.
     */
    private fun isValid(public: LogStarPublic): Boolean {
        if (!public.n0.validateCiphertexts(commitment.A)) return false
        if (commitment.Y.isIdentity()) return false
        if (!isValidModN(public.n0.n, z2)) return false
        return true
    }

    companion object {
        /**
         * Creates a new proof based on public and private parameters.
         *
         * @param id The identifier for the session or proof.
         * @param public The public parameters for the proof.
         * @param private The private parameters for the proof.
         * @return The newly created proof.
         */
        fun newProof(id: Int, public: LogStarPublic, private: LogStarPrivate): LogStarProof {
            val n = public.n0.n

            val alpha = sampleLEps()
            val r = sampleModNStar(n)
            val mu = sampleLN()
            val gamma = sampleLEpsN()

            val commitment = LogStarCommitment(
                A = public.n0.encryptWithNonce(alpha, r),
                Y = Scalar(alpha.mod(secp256k1Order())).act(public.g),
                S = public.aux.calculateCommit(private.x, mu),
                D = public.aux.calculateCommit(alpha, gamma)
            )

            val e = challenge(id, public, commitment)

            val z1 = e.multiply(private.x).add(alpha)

            val z2 = private.rho.modPow(e, n).multiply(r).mod(n)

            val z3 = e.multiply(mu).add(gamma)

            return LogStarProof(commitment, z1, z2, z3)
        }

        /**
         * Generates a challenge based on public parameters and the commitment.
         *
         * @param id The identifier for the session or proof.
         * @param public The public parameters.
         * @param commitment The commitment associated with the proof.
         * @return The generated challenge value.
         */
        private fun challenge(id: Int, public: LogStarPublic, commitment: LogStarCommitment): BigInteger {
            // Collect relevant parts to form the challenge
            val inputs = listOf<BigInteger>(
                public.aux.n,
                public.aux.s,
                public.aux.t,
                public.n0.n,
                public.C.value(),
                public.X.x,
                public.X.y,
                public.g.x,
                public.g.y,
                commitment.S,
                commitment.A.value(),
                commitment.Y.x,
                commitment.Y.y,
                commitment.D,
                BigInteger.valueOf(id.toLong())
            )
            val e = inputs.fold(BigInteger.ZERO) { acc, value -> acc.add(value).mod(secp256k1Order()) }.mod(secp256k1Order())
            return e
        }
    }

    /**
     * Verifies the proof's integrity and correctness against public parameters.
     *
     * @param id The identifier for the session or proof.
     * @param public The public parameters used for verification.
     * @return True if the proof is verified, false otherwise.
     */
    fun verify(id: Int, public: LogStarPublic): Boolean {
        if (!isValid(public)) {
            return false
        }

        if (!isInIntervalLEps(z1)) {
            return false
        }

        val e = challenge(id, public, commitment)

        if (!public.aux.verifyCommit(z1, z3, e, commitment.D, commitment.S)) {
            return false
        }

        val lhs = public.n0.encryptWithNonce(z1, z2)
        val rhs = (public.C.clone().modPowNSquared(public.n0, e)).modMulNSquared(public.n0, commitment.A)
        if (lhs != rhs)  {
            return false
        }

        val lhsPoint = Scalar(z1).act(public.g)
        val rhsPoint = commitment.Y.add(Scalar(e).act(public.X))
        if (lhsPoint != rhsPoint) {
            return false
        }
        return true
    }
}