package perun_network.ecdsa_threshold.zk.affg

import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.math.curve.Curve
import perun_network.ecdsa_threshold.math.curve.Point
import perun_network.ecdsa_threshold.math.isInIntervalLEps
import perun_network.ecdsa_threshold.math.isInIntervalLPrimeEps
import perun_network.ecdsa_threshold.math.isValidBigModN
import perun_network.ecdsa_threshold.math.sample.*
import perun_network.ecdsa_threshold.math.sample.intervalScalar
import perun_network.ecdsa_threshold.protocols.cmp.paillier.CipherText
import perun_network.ecdsa_threshold.protocols.cmp.paillier.PublicKey
import perun_network.ecdsa_threshold.protocols.cmp.pedersen.Parameters
import java.math.BigInteger
import java.security.SecureRandom

data class Public (
    val kv: CipherText,
    val dv: CipherText,
    val fp: CipherText,
    val xp: Point,
    val prover: PublicKey,
    val verifier: PublicKey,
    val aux: Parameters
)

data class Private(
    val X: BigInteger, //
    val Y: BigInteger,   // Y = y
    val S: BigInteger,   // S = s (Original name: ρ)
    val R: BigInteger    // R = r (Original name: ρy)
)

data class Commitment(
    val A: CipherText?, // A = (α ⊙ C) ⊕ Encᵥ(β, ρ)
    val Bx: Point,        // Bₓ = α⋅G
    val By: CipherText?, // By = Encₚ(β, ρy)
    val E: BigInteger?,         // E = sᵃ tᵍ (mod N)
    val S: BigInteger?,         // S = sˣ tᵐ (mod N)
    val F: BigInteger?,         // F = sᵇ tᵈ (mod N)
    val T: BigInteger?          // T = sʸ tᵘ (mod N)
)

class Proof(
    val group: Curve,
    val commitment: Commitment,
    val Z1: BigInteger?,  // Z1 = Z₁ = α + e⋅x
    val Z2: BigInteger?,  // Z2 = Z₂ = β + e⋅y
    val Z3: BigInteger?,  // Z3 = Z₃ = γ + e⋅m
    val Z4: BigInteger?,  // Z4 = Z₄ = δ + e⋅μ
    val W: BigInteger?,   // W = w = ρ⋅sᵉ (mod N₀)
    val Wy: BigInteger?   // Wy = wy = ρy⋅rᵉ (mod N₁)
) {
    fun isValid(public: Public): Boolean {
        if (!public.verifier.validateCiphertexts(commitment.A!!) ||
            !public.prover.validateCiphertexts(commitment.By!!)) return false
        if (!isValidBigModN(public.prover.modulus(), Wy)) return false
        if (!isValidBigModN(public.verifier.modulus(), W)) return false
        if (commitment.Bx.isIdentity()) return false
        return true
    }

    fun verify(hash: Hash, public: Public): Boolean {
        if (!isValid(public)) return false

        val verifier = public.verifier
        val prover = public.prover

        if (!isInIntervalLEps(Z1)) return false
        if (!isInIntervalLPrimeEps(Z2)) return false

        val e = challenge(hash, group, public, commitment) ?: return false

        if (!public.aux.verify(Z1!!, Z3!!, e, commitment.E!!, commitment.S!!)) return false
        if (!public.aux.verify(Z2!!, Z4!!, e, commitment.F!!, commitment.T!!)) return false

        // Verifying the conditions
        val tmp = public.kv.clone().mul(verifier, Z1)
        val lhs = verifier.encWithNonce(Z2!!, W!!).add(verifier, tmp)
        val rhs = public.dv.clone().mul(verifier, e).add(verifier, commitment.A)

        if (!lhs.equals(rhs)) return false

        val lhsPoint = group.newScalar().setNat(Z1.mod(group.order())).actOnBase()
        val rhsPoint = group.newScalar().setNat(e.mod(group.order())).act(public.xp).add(commitment.Bx)

        if (!lhsPoint.equals(rhsPoint)) return false

        val lhsEnc = prover.encWithNonce(Z2, Wy!!)
        val rhsEnc = public.fp.clone().mul(prover, e).add(prover, commitment.By)

        if (!lhsEnc.equals(rhsEnc)) return false

        return true
    }

    companion object {
        fun challenge(hash: Hash, group: Curve, public: Public, commitment: Commitment): BigInteger? {
            return try {
                hash.writeAny(public.aux, public.prover, public.verifier, public.kv, public.dv, public.fp, public.xp,
                    commitment.A!!, commitment.Bx, commitment.By!!, commitment.E!!, commitment.S!!, commitment.F!!, commitment.T!!)

                return intervalScalar(hash.digest().inputStream(), group)
            } catch (e: Exception) {
                null
            }
        }

        fun empty(group: Curve): Proof {
            return Proof(
                group = group,
                commitment = Commitment(
                    A = null,
                    Bx = group.newPoint(),
                    By = null,
                    E = null,
                    S = null,
                    F = null,
                    T = null
                ),
                Z1 = null,
                Z2 = null,
                Z3 = null,
                Z4 = null,
                W = null,
                Wy = null
            )
        }

        fun newProof(group: Curve, hash: Hash, public: Public, private: Private): Proof {
            val N0 = public.verifier.modulus()
            val N1 = public.prover.modulus()

            val verifier = public.verifier
            val prover = public.prover

            val secureRandomInputStream = SecureRandomInputStream(SecureRandom())

            val alpha = intervalLEps(secureRandomInputStream)
            val beta = intervalLPrimeEps(secureRandomInputStream)

            val rho = unitModN(secureRandomInputStream, N0)
            val rhoY = unitModN(secureRandomInputStream, N1)

            val gamma = intervalLEpsN(secureRandomInputStream)
            val m = intervalLN(secureRandomInputStream)
            val delta = intervalLEpsN(secureRandomInputStream)
            val mu = intervalLN(secureRandomInputStream)

            val cAlpha = public.kv.clone().mul(verifier, alpha) // Cᵃ mod N₀ = α ⊙ Kv
            val A = verifier.encWithNonce(beta, rho).add(verifier, cAlpha) // Enc₀(β,ρ) ⊕ (α ⊙ Kv)

            val E = public.aux.commit(alpha, gamma)
            val S = public.aux.commit(private.X, m)
            val F = public.aux.commit(beta, delta)
            val T = public.aux.commit(private.Y, mu)

            val commitment = Commitment(
                A = A,
                Bx = group.newScalar().setNat(alpha.mod(group.order())).actOnBase(),
                By = prover.encWithNonce(beta, rhoY),
                E = E,
                S = S,
                F = F,
                T = T
            )

            val e = challenge(hash, group, public, commitment) ?: BigInteger.ZERO

            val z1 = private.X.multiply(e).negate().add(alpha) // e•x+α
            val z2 = private.Y.multiply(e).negate().add(beta) // e•y+β
            val z3 = m.multiply(e).negate().add(gamma) // e•m+γ
            val z4 = mu.multiply(e).negate().add(delta) // e•μ+δ

            val w = N0.modPow(private.S, e).multiply(rho).mod(N0) // ρ⋅sᵉ mod N₀
            val wY = N1.modPow(private.R, e).multiply(rhoY).mod(N1) // ρy⋅rᵉ mod N₁

            return Proof(
                group = group,
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