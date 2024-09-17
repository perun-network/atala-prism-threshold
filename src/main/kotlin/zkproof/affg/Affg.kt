package perun_network.ecdsa_threshold.zkproof.affg

import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.ecdsa.secp256k1Order
import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.math.*
import perun_network.ecdsa_threshold.paillier.PaillierCipherText
import perun_network.ecdsa_threshold.paillier.PaillierPublic
import perun_network.ecdsa_threshold.pedersen.PedersenParameters
import java.math.BigInteger

data class AffgPublic (
    val kv: PaillierCipherText, // Kv is a ciphertext encrypted with Nᵥ
    val dv: PaillierCipherText, //  Dv = (x ⨀ Kv) ⨁ Encᵥ(y;s)
    val fp: PaillierCipherText, // Fp = Encₚ(y;r)
    val xp: Point,  // Xp = gˣ
    val prover: PaillierPublic, // Prover = Nₚ
    val verifier: PaillierPublic,   // Verifier = Nᵥ
    val aux: PedersenParameters
)

data class AffgPrivate(
    val X: BigInteger, // X = x
    val Y: BigInteger,   // Y = y
    val S: BigInteger,   // S = s (Original name: ρ)
    val R: BigInteger    // R = r (Original name: ρy)
)

data class AffgCommitment(
    val A: PaillierCipherText, // A = (α ⊙ C) ⊕ Encᵥ(β, ρ)
    val Bx: Point,        // Bₓ = α⋅G
    val By: PaillierCipherText, // By = Encₚ(β, ρy)
    val E: BigInteger?,         // E = sᵃ tᵍ (mod N)
    val S: BigInteger?,         // S = sˣ tᵐ (mod N)
    val F: BigInteger?,         // F = sᵇ tᵈ (mod N)
    val T: BigInteger?          // T = sʸ tᵘ (mod N)
)

class Proof(
    val commitment: AffgCommitment,
    val Z1: BigInteger?,  // Z1 = Z₁ = α + e⋅x
    val Z2: BigInteger?,  // Z2 = Z₂ = β + e⋅y
    val Z3: BigInteger?,  // Z3 = Z₃ = γ + e⋅m
    val Z4: BigInteger?,  // Z4 = Z₄ = δ + e⋅μ
    val W: BigInteger?,   // W = w = ρ⋅sᵉ (mod N₀)
    val Wy: BigInteger?   // Wy = wy = ρy⋅rᵉ (mod N₁)
) {
    fun isValid(public: AffgPublic): Boolean {
        if (!public.verifier.validateCiphertexts(commitment.A!!) ||
            !public.prover.validateCiphertexts(commitment.By!!)) return false
        if (!isValidBigModN(public.prover.n, Wy)) return false
        if (!isValidBigModN(public.verifier.n, W)) return false
        if (commitment.Bx.isIdentity()) return false
        return true
    }

    fun verify(hash: Hash, public: AffgPublic): Boolean {
        if (!isValid(public)) return false

        val verifier = public.verifier
        val prover = public.prover

        if (!isInIntervalLEps(Z1)) return false
        if (!isInIntervalLPrimeEps(Z2)) return false

        val e = challenge(hash, public, commitment) ?: return false

        if (!public.aux.verify(Z1!!, Z3!!, e, commitment.E!!, commitment.S!!)) return false
        if (!public.aux.verify(Z2!!, Z4!!, e, commitment.F!!, commitment.T!!)) return false

        // Verifying the conditions
        val tmp = public.kv.clone().mul(verifier, Z1)
        val lhs = verifier.encWithNonce(Z2!!, W!!).add(verifier, tmp)
        val rhs = public.dv.clone().mul(verifier, e).add(verifier, commitment.A)

        if (lhs != rhs) return false

        val lhsPoint = Scalar(Z1.mod(secp256k1Order())).actOnBase()
        val rhsPoint = Scalar(e.mod(secp256k1Order())).act(public.xp).add(commitment.Bx)

        if (lhsPoint != rhsPoint) return false

        val lhsEnc = prover.encWithNonce(Z2, Wy!!)
        val rhsEnc = public.fp.clone().mul(prover, e).add(prover, commitment.By)

        if (lhsEnc != rhsEnc) return false

        return true
    }

    companion object {
        fun challenge(hash: Hash, public: AffgPublic, commitment: AffgCommitment): BigInteger? {
            return try {
                hash.writeAny(public.aux, public.prover, public.verifier, public.kv, public.dv, public.fp, public.xp,
                    commitment.A!!, commitment.Bx, commitment.By!!, commitment.E!!, commitment.S!!, commitment.F!!, commitment.T!!)

                return intervalScalar(hash.digest().inputStream())
            } catch (e: Exception) {
                null
            }
        }


        fun newProof(hash: Hash, public: AffgPublic, private: AffgPrivate): Proof {
            val N0 = public.verifier.n
            val N1 = public.prover.n

            val verifier = public.verifier
            val prover = public.prover


            val alpha = intervalLEps()
            val beta = intervalLPrimeEps()

            val rho = unitModN(N0)
            val rhoY = unitModN(N1)

            val gamma = intervalLEpsN()
            val m = intervalLN()
            val delta = intervalLEpsN()
            val mu = intervalLN()

            val cAlpha = public.kv.clone().mul(verifier, alpha) // Cᵃ mod N₀ = α ⊙ Kv
            val A = verifier.encWithNonce(beta, rho).add(verifier, cAlpha) // Enc₀(β,ρ) ⊕ (α ⊙ Kv)

            val E = public.aux.commit(alpha, gamma)
            val S = public.aux.commit(private.X, m)
            val F = public.aux.commit(beta, delta)
            val T = public.aux.commit(private.Y, mu)

            val commitment = AffgCommitment(
                A = A,
                Bx = Scalar(alpha.mod(secp256k1Order())).actOnBase(),
                By = prover.encWithNonce(beta, rhoY),
                E = E,
                S = S,
                F = F,
                T = T
            )

            val e = challenge(hash, public, commitment) ?: BigInteger.ZERO

            val z1 = private.X.multiply(e).negate().add(alpha) // e•x+α
            val z2 = private.Y.multiply(e).negate().add(beta) // e•y+β
            val z3 = m.multiply(e).negate().add(gamma) // e•m+γ
            val z4 = mu.multiply(e).negate().add(delta) // e•μ+δ

            val w = N0.modPow(private.S, e).multiply(rho).mod(N0) // ρ⋅sᵉ mod N₀
            val wY = N1.modPow(private.R, e).multiply(rhoY).mod(N1) // ρy⋅rᵉ mod N₁

            return Proof(
                commitment = commitment,
                Z1 = z1,
                Z2 = z2,
                Z3 = z3,
                Z4 = z4,
                W = w,
                Wy = wY
            )
        }
    }
}