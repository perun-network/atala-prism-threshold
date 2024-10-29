package perun_network.ecdsa_threshold.zkproof.enc

import perun_network.ecdsa_threshold.ecdsa.secp256k1Order
import perun_network.ecdsa_threshold.math.*
import perun_network.ecdsa_threshold.paillier.PaillierCipherText
import perun_network.ecdsa_threshold.paillier.PaillierPublic
import perun_network.ecdsa_threshold.pedersen.PedersenParameters
import java.math.BigInteger

/**
 * Represents the public parameters for the Π_enc (Paillier Encryption in Range ZK) zero-knowledge proof.
 * The following relation verifies that the plaintext value of Paillier
 * ciphertext C is in a desired range I = ±2^l
 *
 * @property K The public ciphertext related to the public key.
 * @property n0 The Paillier public key used for encryption.
 * @property aux The Pedersen parameters used for commitment.
 */
data class EncPublic(
    val K: PaillierCipherText,
    val n0: PaillierPublic,
    val aux: PedersenParameters
)

/**
 * Represents the private parameters for the Π_enc (Paillier Encryption in Range ZK) zero-knowledge proof.
 *
 * @property k The private key component, calculated as k ∈ 2ˡ = Dec₀(K).
 * @property rho The random value ρ used in the proof.
 */
data class EncPrivate(
    val k: BigInteger,
    val rho: BigInteger
)

/**
 * Represents the commitment values used in the Π_enc (Paillier Encryption in Range ZK) zero-knowledge proof.
 *
 * @property S The value calculated as S = sᵏtᵘ.
 * @property A The ciphertext calculated from the first private parameter.
 * @property C The value calculated as C = sᵃtᵍ.
 */
data class EncCommitment(
    val S: BigInteger,
    val A: PaillierCipherText,
    val C: BigInteger
)

/**
 * Represents the proof in the Π_enc (Paillier Encryption in Range ZK) protocol.
 *
 * @property commitment The commitment associated with this proof.
 * @property z1 The value calculated as z₁ = α + e⋅k.
 * @property z2 The value calculated as z₂ = r ⋅ ρᵉ (mod N₀).
 * @property z3 The value calculated as z₃ = γ + e⋅μ.
 */
data class EncProof(
    val commitment: EncCommitment,
    val z1: BigInteger,
    val z2: BigInteger,
    val z3: BigInteger
) {
    /**
     * Validates the proof against the provided public parameters.
     *
     * @param public The public parameters against which to validate the proof.
     * @return True if the proof is valid, false otherwise.
     */
    private fun isValid(public: EncPublic): Boolean {
        return public.n0.validateCiphertexts(commitment.A) &&
                isValidModN(public.n0.n, z2)
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
        fun newProof(id: Int, public: EncPublic, private: EncPrivate): EncProof {
            val n = public.n0.n

            val alpha = sampleLEps()
            val r = sampleModN(n)
            val mu = sampleLN()
            val gamma = sampleLEpsN()

            val A = public.n0.encryptWithNonce(alpha, r)

            val commitment = EncCommitment(
                S = public.aux.calculateCommit(private.k, mu),
                A = A,
                C = public.aux.calculateCommit(alpha, gamma)
            )

            val e = challenge(id, public, commitment)

            val z1 = (private.k.multiply(e)).add(alpha)

            val z2 = (private.rho.modPow(e, n)).multiply(r).mod(n)
            val z3 = (e.multiply(mu)).add(gamma)
            return EncProof(commitment, z1, z2, z3)
        }

        /**
         * Generates a challenge based on public parameters and the commitment.
         *
         * @param id The identifier for the session or proof.
         * @param public The public parameters.
         * @param commitment The commitment associated with the proof.
         * @return The generated challenge value.
         */
        private fun challenge(id: Int, public: EncPublic, commitment: EncCommitment): BigInteger {
            // Collect relevant parts to form the challenge
            val inputs = listOf<BigInteger>(
                public.n0.n,
                public.K.c,
                commitment.S,
                commitment.A.c,
                commitment.C,
                BigInteger.valueOf(id.toLong())
            )
            return inputs.fold(BigInteger.ZERO) { acc, value -> acc.add(value).mod(secp256k1Order()) }.mod(secp256k1Order())
        }
    }

    /**
     * Verifies the proof's integrity and correctness against public parameters.
     *
     * @param id The identifier for the session or proof.
     * @param public The public parameters used for verification.
     * @return True if the proof is verified, false otherwise.
     */
    fun verify(id: Int, public: EncPublic): Boolean {
        if (!isValid(public)) return false

        val prover = public.n0

        if (!isInIntervalLEps(z1)) return false

        val e = challenge(id, public, commitment)

        if (!public.aux.verifyCommit(z1, z3, e, commitment.C, commitment.S)) return false

        val lhs = prover.encryptWithNonce(z1, z2)
        val rhs = (public.K.modPowNSquared(prover, e)).modMulNSquared(prover, commitment.A)

        return lhs == rhs
    }
}