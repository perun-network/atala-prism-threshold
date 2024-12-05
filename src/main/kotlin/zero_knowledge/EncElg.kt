package perun_network.ecdsa_threshold.zero_knowledge

import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.ecdsa.secp256k1Order
import perun_network.ecdsa_threshold.math.*
import perun_network.ecdsa_threshold.paillier.PaillierCipherText
import perun_network.ecdsa_threshold.paillier.PaillierPublic
import perun_network.ecdsa_threshold.pedersen.PedersenParameters
import java.math.BigInteger

/**
 * Public parameters for the Range Proof w/ EL-Gamal Commitment (Enc-Elg) zero-knowledge proof.
 *
 * @property C Paillier ciphertext representing an encrypted message.
 * @property A Elliptic curve point representing g^a.
 * @property B Elliptic curve point representing g^b.
 * @property X Elliptic curve point representing g^(a*b + x).
 * @property N0 Paillier public key for the prover.
 * @property aux Pedersen parameters for commitment schemes.
 */
data class EncElgPublic (
    val C: PaillierCipherText,
    val A: Point, // g^a
    val B: Point, // g^b
    val X: Point, // g^(a*b+x)

    val N0: PaillierPublic,
    val aux: PedersenParameters
)

/**
 * Private parameters for the Range Proof w/ EL-Gamal Commitment (Enc-Elg) zero-knowledge proof.
 *
 * @property x Private scalar value, representing the decrypted value of C.
 * @property rho Random nonce associated with the encryption of C.
 * @property a Scalar value a used in the ElGamal encryption.
 * @property b Scalar value b used in the ElGamal encryption.
 */
data class EncElgPrivate (
    val x : BigInteger, // x= dec(C)
    val rho: BigInteger, // rho = Nonce(C)
    val a: Scalar,
    val b: Scalar,
)

/**
 * Commitment values generated during the zero-knowledge proof.
 *
 * @property S Commitment based on x and a random value.
 * @property D Paillier ciphertext representing the encryption of alpha.
 * @property Y Elliptic curve point representing A^β * G^α.
 * @property Z Elliptic curve point representing G^β.
 * @property T Pedersen commitment based on alpha and a random value.
 */
data class EncElgCommitment(
    val S : BigInteger, // S = sˣtᵘ
    val D : PaillierCipherText, // D = Enc(α, r)
    val Y: Point, // Y = A^β*G^α
    val Z: Point, // Z = G^β
    val T: BigInteger // C = sᵃtᵍ
)

/**
 * The zero-knowledge proof for the Range Proof w/ EL-Gamal Commitment (Enc-Elg).
 *
 * @property commitment The commitments made during the proof.
 * @property z1 Scalar representing α + ex.
 * @property w Scalar representing β + eb (mod q).
 * @property z2 Scalar representing r⋅ρᵉ (mod N₀).
 * @property z3 Scalar representing γ + eμ.
 */
data class EncElgProof (
    val commitment: EncElgCommitment,
    val z1: BigInteger, // z₁ = α + ex
    val w: Scalar, // w = β + eb (mod q)
    val z2: BigInteger, // z₂ = r⋅ρᵉ (mod N₀)
    val z3: BigInteger, // z₃ = γ + eμ
) {
    /**
     * Validates the proof against the provided public parameters.
     *
     * @param public The public parameters against which to validate the proof.
     * @return True if the proof is valid, false otherwise.
     */
    private fun isValid(public: EncElgPublic): Boolean {
        if (!public.N0.validateCiphertexts(commitment.D)) {
            return false
        }

        if (w.isZero() || commitment.Y.isIdentity() || commitment.Z.isIdentity()) {
            return false
        }
        return isValidModN(public.N0.n, z2)
    }

    /**
     * Verifies the proof's integrity and correctness against public parameters.
     *
     * @param id The identifier for the session or proof.
     * @param public The public parameters used for verification.
     * @return True if the proof is verified, false otherwise.
     */
    fun verify(id: Int, public: EncElgPublic): Boolean {
        if (!isValid(public)) return false

        val prover = public.N0

        if (!isInIntervalLEps(z1)) return false

        val e = challenge(id, public, commitment)

        // Enc(z₁;z₂) == D * C^e mod N0²
        if (prover.encryptWithNonce(z1, z2) != (public.C.modPowNSquared(prover, e)).modMulNSquared(prover, commitment.D)) {
            return false
        }

        // A^w * G^z1 == Y*X^e
        if (
            Scalar.scalarFromBigInteger(z1).actOnBase().add(w.act(public.A)) !=
            Scalar.scalarFromBigInteger(e).act(public.X).add(commitment.Y)) {
            return false
        }

        // G^w == Z*B^e
        if (w.actOnBase() != commitment.Z.add(Scalar.scalarFromBigInteger(e).act(public.B))) {
            return false
        }

        // s^z1 * t^z3 = T · S^e
        if (!public.aux.verifyCommit(z1, z3, e, commitment.T, commitment.S)) return false
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
        fun newProof(id: Int, public: EncElgPublic, private: EncElgPrivate): EncElgProof {
            val n = public.N0.n

            val alpha = sampleLEps()
            val r = sampleModNStar(n)
            val mu = sampleLN()
            val beta = sampleScalar()
            val gamma = sampleLEpsN()

            val S = public.aux.calculateCommit(private.x, mu)
            val D = public.N0.encryptWithNonce(alpha, r)
            val Y = beta.act(public.A).add(Scalar.scalarFromBigInteger(alpha).actOnBase())
            val Z = beta.actOnBase()
            val T = public.aux.calculateCommit(alpha, gamma)

            val commitment = EncElgCommitment(S, D, Y, Z, T)

            val e = challenge(id, public, commitment)

            val z1 = (private.x.multiply(e)).add(alpha)
            val w = beta.add(Scalar.scalarFromBigInteger(e).multiply(private.b))
            val z2 = (private.rho.modPow(e, n)).multiply(r).mod(n)
            val z3 = (e.multiply(mu)).add(gamma)
            return EncElgProof(commitment, z1, w, z2, z3)
        }

        /**
         * Generates a challenge based on public parameters and the commitment.
         *
         * @param id The identifier for the session or proof.
         * @param public The public parameters.
         * @param commitment The commitment associated with the proof.
         * @return The generated challenge value.
         */
        private fun challenge(id: Int, public: EncElgPublic, commitment: EncElgCommitment): BigInteger {
            // Collect relevant parts to form the challenge
            val inputs = listOf<BigInteger>(
                public.N0.n,
                public.C.c,
                public.B.x,
                public.B.y,
                public.A.x,
                public.A.y,
                public.X.x,
                public.X.y,
                commitment.S,
                commitment.D.value(),
                commitment.Y.x,
                commitment.Y.y,
                commitment.Z.x,
                commitment.Z.y,
                commitment.T,
                BigInteger.valueOf(id.toLong())
            )
            return inputs.fold(BigInteger.ZERO) { acc, value -> acc.add(value).mod(secp256k1Order()) }.mod(
                secp256k1Order()
            )
        }
    }
}