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


data class AffgPublic (
    val C: PaillierCipherText,
    val D: PaillierCipherText,
    val Y: PaillierCipherText,
    val X: Point,
    val n0: PaillierPublic, // verifier
    val n1: PaillierPublic, // prover
    val aux: PedersenParameters
)

data class AffgPrivate(
    val x: BigInteger, // x
    val y: BigInteger,   // y
    val rho: BigInteger,   // ρ
    val rhoY: BigInteger    // ρy
)

data class AffgCommitment(
    val A: PaillierCipherText, // A = (α ⊙ C) ⊕ Encᵥ(β, ρ)
    val Bx: Point,        // Bₓ = α⋅G
    val By: PaillierCipherText, // By = Encₚ(β, ρy)
    val E: BigInteger,         // E = sᵃ tᵍ (mod N)
    val S: BigInteger,         // S = sˣ tᵐ (mod N)
    val F: BigInteger,         // F = sᵇ tᵈ (mod N)
    val T: BigInteger          // T = sʸ tᵘ (mod N)
)

class AffgProof(
    val commitment: AffgCommitment,
    val z1: BigInteger,  // z1 = α + e⋅x
    val z2: BigInteger,  // z2 = β + e⋅y
    val z3: BigInteger,  // z3 = γ + e⋅m
    val z4: BigInteger,  // z4 = δ + e⋅μ
    val w: BigInteger,   // w = ρ⋅sᵉ (mod N₀)
    val wY: BigInteger   // wY = ρy⋅rᵉ (mod N₁)
) {
    fun isValid(public: AffgPublic): Boolean {
        if (!public.n1.validateCiphertexts(commitment.A)) return false
        if (!public.n0.validateCiphertexts(commitment.By)) return false
        if (!isValidModN(public.n1.n, wY)) return false
        if (!isValidModN(public.n0.n, w)) return false
        if (commitment.Bx.isIdentity()) return false
        return true
    }

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
        // 1st condition
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
