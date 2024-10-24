package perun_network.ecdsa_threshold.zkproof.affg

import com.ionspin.kotlin.bignum.integer.Quadruple
import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.ecdsa.secp256k1Order
import perun_network.ecdsa_threshold.math.*
import perun_network.ecdsa_threshold.paillier.PaillierCipherText
import perun_network.ecdsa_threshold.paillier.PaillierPublic
import perun_network.ecdsa_threshold.paillier.PaillierSecret
import perun_network.ecdsa_threshold.pedersen.PedersenParameters
import perun_network.ecdsa_threshold.tuple.Quintuple
import java.math.BigInteger

/**
 * Represents the public parameters for the Aff-g (Paillier Affine Operation with Group Commitment in Range ZK) zero-knowledge proof.
 *
 * @property C The ciphertext related to a certain commitment.
 * @property D Another ciphertext used in the proof.
 * @property Y The ciphertext that will be verified.
 * @property X A point on an elliptic curve, representing a public key.
 * @property n0 The Paillier public key of the verifier.
 * @property n1 The Paillier public key of the prover.
 * @property aux The Pedersen parameters used for commitment.
 */
data class AffgPublic (
    val C: PaillierCipherText,
    val D: PaillierCipherText,
    val Y: PaillierCipherText,
    val X: Point,
    val n0: PaillierPublic, // verifier
    val n1: PaillierPublic, // prover
    val aux: PedersenParameters
)

/**
 * Represents the private parameters for the Aff-g (Paillier Affine Operation with Group Commitment in Range ZK) zero-knowledge proof.
 *
 * @property x The private value used in the proof.
 * @property y Another private value used in the proof.
 * @property rho Random value associated with the first private parameter.
 * @property rhoY Random value associated with the second private parameter.
 */
data class AffgPrivate(
    val x: BigInteger, // x
    val y: BigInteger,   // y
    val rho: BigInteger,   // ρ
    val rhoY: BigInteger    // ρy
)

/**
 * Represents the commitment values used in the zero-knowledge proof.
 *
 * @property A The ciphertext calculated from the commitment parameters.
 * @property Bx The point derived from one of the private parameters.
 * @property By The ciphertext associated with the second private parameter.
 * @property E Various calculated values involved in commitments.
 * @property S Various calculated values involved in commitments.
 * @property F Various calculated values involved in commitments.
 * @property T Various calculated values involved in commitments.
 */
data class AffgCommitment(
    val A: PaillierCipherText, // A = (α ⊙ C) ⊕ Encᵥ(β, ρ)
    val Bx: Point,        // Bₓ = α⋅G
    val By: PaillierCipherText, // By = Encₚ(β, ρy)
    val E: BigInteger,         // E = sᵃ tᵍ (mod N)
    val S: BigInteger,         // S = sˣ tᵐ (mod N)
    val F: BigInteger,         // F = sᵇ tᵈ (mod N)
    val T: BigInteger          // T = sʸ tᵘ (mod N)
)

/**
 * Represents the proof in the Aff-g (Paillier Affine Operation with Group Commitment in Range ZK) zero-knowledge protocol.
 *
 * @property commitment The commitment associated with this proof.
 * @property z1 The value z1 calculated from α and e·x.
 * @property z2 The value z2 calculated from β and e·y.
 * @property z3 The value z3 calculated from γ and e·m.
 * @property z4 The value z4 calculated from δ and e·μ.
 * @property w The value w calculated as ρ·sᵉ (mod N₀).
 * @property wY The value wY calculated as ρy·rᵉ (mod N₁).
 */
class AffgProof(
    val commitment: AffgCommitment,
    val z1: BigInteger,  // z1 = α + e⋅x
    val z2: BigInteger,  // z2 = β + e⋅y
    val z3: BigInteger,  // z3 = γ + e⋅m
    val z4: BigInteger,  // z4 = δ + e⋅μ
    val w: BigInteger,   // w = ρ⋅sᵉ (mod N₀)
    val wY: BigInteger   // wY = ρy⋅rᵉ (mod N₁)
) {
    /**
     * Validates the proof against the provided public parameters.
     *
     * @param public The public parameters against which to validate the proof.
     * @return True if the proof is valid, false otherwise.
     */
    fun isValid(public: AffgPublic): Boolean {
        if (!public.n1.validateCiphertexts(commitment.A)) return false
        if (!public.n0.validateCiphertexts(commitment.By)) return false
        if (!isValidModN(public.n1.n, wY)) return false
        if (!isValidModN(public.n0.n, w)) return false
        if (commitment.Bx.isIdentity()) return false
        return true
    }

    /**
     * Verifies the proof's integrity and correctness against public parameters.
     *
     * @param id The identifier for the session or proof.
     * @param public The public parameters used for verification.
     * @return True if the proof is verified, false otherwise.
     */
    fun verify(id: Int, public: AffgPublic): Boolean {
        if (!isValid(public)) {
            return false
        }

        val n1 = public.n1
        val n0 = public.n0

        if (!isInIntervalLEps(z1)) {
            return false
        }
        if (!isInIntervalLPrimeEps(z2)) {
            return false
        }

        val e = challenge(id, public, commitment)

        if (!public.aux.verifyCommit(z1, z3, e, commitment.E, commitment.S)) {
            return false
        }
        if (!public.aux.verifyCommit(z2, z4, e, commitment.F, commitment.T)) {
            return false
        }

        // Verifying the conditions
        val tmp = public.C.clone().modPowNSquared(n0, z1)
        val lhs = (n0.encryptWithNonce(z2, w)).modMulNSquared(n0, tmp)
        val rhs = (public.D.clone().modPowNSquared(n0, e)).modMulNSquared(n0, commitment.A)

        if (lhs != rhs) {
            return false
        }

        val lhsPoint = Scalar(z1).actOnBase() // g^z1
        val rhsPoint = Scalar(e).act(public.X).add(commitment.Bx)

        if (lhsPoint != rhsPoint) {
            return false
        }


        val lhsEnc = n1.encryptWithNonce(z2, wY)
        val rhsEnc = (public.Y.modPowNSquared(n1, e)).modMulNSquared(n1, commitment.By)

        if (lhsEnc != rhsEnc) {
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
        fun challenge(id: Int, public: AffgPublic, commitment: AffgCommitment): BigInteger {
            // Collect relevant parts to form the challenge
            val inputs = listOf<BigInteger>(
                public.aux.n,
                public.aux.s,
                public.aux.t,
                public.n0.n,
                public.n1.n,
                public.C.value(),
                public.D.value(),
                public.Y.value(),
                public.X.x,
                public.X.y,
                commitment.A.value(),
                commitment.Bx.x,
                commitment.Bx.y,
                commitment.By.value(),
                commitment.E,
                commitment.S,
                commitment.F,
                commitment.T,
                BigInteger.valueOf(id.toLong())
            )
            val e =  inputs.fold(BigInteger.ZERO) { acc, value -> acc.add(value).mod(secp256k1Order()) }.mod(secp256k1Order())
            return e
        }

        /**
         * Creates a new proof based on public and private parameters.
         *
         * @param id The identifier for the session or proof.
         * @param public The public parameters for the proof.
         * @param private The private parameters for the proof.
         * @return The newly created proof.
         */
        fun newProof(id: Int, public: AffgPublic, private: AffgPrivate): AffgProof {
            val n0 = public.n0.n
            val n1 = public.n1.n

            val alpha = sampleLEps() // α ← ±2^(l+ε)
            val beta = sampleLPrimeEps() // β ← ±2^(l'+ε)

            // r ← Z∗N0 , ry ← Z∗N1
            val r = sampleUnitModN(n0)
            val ry = sampleUnitModN(n1)

            // γ ← ±2^l+ε· N, m ˆ ← ±2^l· N
            val gamma = sampleLEpsN()
            val m  = sampleLN()

            // γ ← ±2^l+ε· N, m ˆ ← ±2^l· N
            val delta = sampleLEpsN()
            val mu = sampleLN()

            val cAlpha = public.C.clone().modPowNSquared(public.n0, alpha) // Cᵃ mod N₀ = α ⊙ Kv
            val A = cAlpha.clone().modMulNSquared(public.n0, public.n0.encryptWithNonce(beta, r)) // A = C^α· ((1 + N0)β· rN0 ) mod N²
            val Bx = Scalar(alpha).actOnBase()
            val By = public.n1.encryptWithNonce(beta, ry)

            val E = public.aux.calculateCommit(alpha, gamma)
            val S = public.aux.calculateCommit(private.x, m)
            val F = public.aux.calculateCommit(beta, delta)
            val T = public.aux.calculateCommit(private.y, mu)
            val commitment = AffgCommitment(A, Bx, By, E, S, F, T)

            val e = challenge(id, public, commitment)

            val z1 = private.x.multiply(e).add(alpha) // e•x+α
            val z2 = private.y.multiply(e).add(beta) // e•y+β
            val z3 = m.multiply(e).add(gamma) // e•m+γ
            val z4 = mu.multiply(e).add(delta) // e•μ+δ

            val w = private.rho.modPow(e, n0).multiply(r).mod(n0) // ρ⋅sᵉ mod N₀
            val wY = private.rhoY.modPow(e, n1).multiply(ry).mod(n1) // ρy⋅rᵉ mod N₁

            return AffgProof(
                commitment = commitment,
                z1 = z1,
                z2 = z2,
                z3 = z3,
                z4 = z4,
                w = w,
                wY = wY
            )
        }
    }
}

/**
 * Computes materials needed for the zero-knowledge proof based on secret shares and encryption.
 *
 * @param senderSecretShare The secret share from the sender.
 * @param receiverEncryptedShare The encrypted share from the receiver.
 * @param sender The sender's Paillier secret key.
 * @param receiver The receiver's Paillier public key.
 * @return A quintuple containing computed values necessary for the proof.
 */
fun computeZKMaterials(
    senderSecretShare: BigInteger,
    receiverEncryptedShare: PaillierCipherText,
    sender: PaillierSecret,
    receiver: PaillierPublic
): Quintuple<
        PaillierCipherText,
        PaillierCipherText,
        BigInteger,
        BigInteger,
        BigInteger
        > {
    val y = sampleLPrime()

    val (Y, rhoY) = sender.publicKey.encryptRandom(y)

    val (D, rho) = receiver.encryptRandom(y)
    val tmp = receiverEncryptedShare.clone().modPowNSquared(receiver, senderSecretShare)
    val delta  = D.modMulNSquared(receiver, tmp)

    return Quintuple(delta, Y, rho, rhoY, y)
}

/**
 * Produces the necessary materials for the Affg protocol, including proof and commitments.
 *
 * @param id The identifier for the session or proof.
 * @param senderSecretShare The secret share of the sender.
 * @param senderSecretSharePoint The corresponding point on the elliptic curve.
 * @param receiverEncryptedShare The encrypted share from the receiver.
 * @param sender The sender's Paillier secret key.
 * @param receiver The receiver's Paillier public key.
 * @param verifier The Pedersen parameters for verification.
 * @return A quadruple containing the generated materials, including the proof.
 */
fun produceAffGMaterials(
    id: Int,
    senderSecretShare: BigInteger, // senderSecretShare = aᵢ
    senderSecretSharePoint: Point, // senderSecretSharePoint = Aᵢ = aᵢ⋅G
    receiverEncryptedShare: PaillierCipherText, // receiverEncryptedShare = Encⱼ(bⱼ)
    sender: PaillierSecret,
    receiver: PaillierPublic,
    verifier: PedersenParameters
): Quadruple<
        BigInteger, // beta = β
        PaillierCipherText, // D = (aⱼ ⊙ Bᵢ) ⊕ encᵢ(- β, s)
        PaillierCipherText, // Y = encⱼ(-β, r)
        AffgProof   // Proof = zkaffg proof of correct encryption.
        > {
    val (D, Y, rho, rhoY, y) = computeZKMaterials(senderSecretShare, receiverEncryptedShare, sender, receiver)
    val proof = AffgProof.newProof(
        id,
        AffgPublic(
            C = receiverEncryptedShare,
            D = D,
            Y = Y,
            X = senderSecretSharePoint,
            n0 = receiver,
            n1 = sender.publicKey,
            aux = verifier
        ), AffgPrivate(
            x = senderSecretShare,
            y = y,
            rho = rho,
            rhoY= rhoY
        )
    )
    val beta = y.negate()
    return Quadruple(beta, D, Y, proof)
}
