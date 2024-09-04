package perun_network.ecdsa_threshold.zk.affp

import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.math.curve.Curve
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

data class Public(
    val kv: CipherText,
    val dv: CipherText,
    val fp: CipherText,
    val xp: CipherText,
    val prover: PublicKey,
    val verifier: PublicKey,
    val aux: Parameters
)

data class Private(
    val x: BigInteger, // X ∈ ± 2ˡ
    val y: BigInteger, // Y ∈ ± 2ˡº
    val s: BigInteger, // S = s (Original name: ρ)
    val rx: BigInteger, // Rx = rₓ (Original name: ρx)
    val r: BigInteger // R = r (Original name: ρy)
)

data class Commitment(
    val a: CipherText?, // A = (α ⊙ Kv) ⊕ Enc₀(β; ρ)
    val bx: CipherText?, // Bx = Enc₁(α;ρₓ)
    val by: CipherText?, // By = Enc₁(β;ρy)
    val e: BigInteger?, // E = sᵃ tᵍ (mod N)
    val s: BigInteger?, // S = sˣ tᵐ (mod N)
    val f: BigInteger?, // F = sᵇ tᵈ (mod N)
    val t: BigInteger? // T = sʸ tᵘ (mod N)
)

class Proof(
    val group: Curve,
    val commitment: Commitment,
    val z1: BigInteger?, // Z1 = Z₁ = α + ex
    val z2: BigInteger?, // Z2 = Z₂ = β + ey
    val z3: BigInteger?, // Z3 = Z₃ = γ + em
    val z4: BigInteger?, // Z4 = Z₄ = δ + eμ
    val w: BigInteger?, // W = w = ρ⋅sᵉ (mod N₀)
    val wx: BigInteger?, // Wx = wₓ = ρₓ⋅rₓᵉ (mod N₁)
    val wy: BigInteger? // Wy = wy = ρy⋅rᵉ (mod N₁)
) {

    fun isValid(public: Public): Boolean {
        if (!public.verifier.validateCiphertexts(commitment.a!!) ||
            !public.prover.validateCiphertexts(commitment.bx!!, commitment.by!!)
        ) return false
        if (!isValidBigModN(public.prover.modulus(), wx, wy)) return false
        if (!isValidBigModN(public.verifier.modulus(), w)) return false
        return true
    }

    fun verify(group : Curve, hash: Hash, public: Public): Boolean {
        if (!isValid(public)) return false

        val verifier = public.verifier
        val prover = public.prover

        if (!isInIntervalLEps(z1)) return false
        if (!isInIntervalLPrimeEps(z2)) return false

        val e = challenge(hash, group, public, commitment) ?: return false

        // Verifying the conditions
        val tmp = public.kv.clone().mul(verifier, z1)
        val lhs = verifier.encWithNonce(z2!!, w!!).add(verifier, tmp)
        val rhs = public.dv.clone().mul(verifier, e).add(verifier, commitment.a)

        if (!lhs.equals(rhs)) return false

        val lhsEncX = prover.encWithNonce(z1!!, wx!!)
        val rhsEncX = public.xp.clone().mul(prover, e).add(prover, commitment.bx)

        if (!lhsEncX.equals(rhsEncX)) return false

        val lhsEncY = prover.encWithNonce(z2, wy!!)
        val rhsEncY = public.fp.clone().mul(prover, e).add(prover, commitment.by)

        if (!lhsEncY.equals(rhsEncY)) return false

        if (!public.aux.verify(z1!!, z3!!, e, commitment.e!!, commitment.s!!)) return false

        if (!public.aux.verify(z2!!, z4!!, e, commitment.f!!, commitment.t!!)) return false

        return true
    }

    companion object {
        fun challenge(hash: Hash, group: Curve, public: Public, commitment: Commitment): BigInteger? {
            return try {
                hash.writeAny(
                    public.aux, public.prover, public.verifier,
                    public.kv, public.dv, public.fp, public.xp,
                    commitment.a!!, commitment.bx!!, commitment.by!!,
                    commitment.e!!, commitment.s!!, commitment.f!!, commitment.t!!
                )
                intervalScalar(hash.digest().inputStream(), group)
            } catch (e: Exception) {
                null
            }
        }

        fun newProof(group: Curve, hash: Hash, public: Public, private: Private): Proof {
            val verifier = public.verifier
            val prover = public.prover

            val alpha = intervalLEps(SecureRandomInputStream(SecureRandom()))
            val beta = intervalLPrimeEps(SecureRandomInputStream(SecureRandom()))

            val rho = unitModN(SecureRandomInputStream(SecureRandom()), verifier.modulus())
            val rhoX = unitModN(SecureRandomInputStream(SecureRandom()), prover.modulus())
            val rhoY = unitModN(SecureRandomInputStream(SecureRandom()), prover.modulus())

            val gamma = intervalLEpsN(SecureRandomInputStream(SecureRandom()))
            val m = intervalLN(SecureRandomInputStream(SecureRandom()))
            val delta = intervalLEpsN(SecureRandomInputStream(SecureRandom()))
            val mu = intervalLN(SecureRandomInputStream(SecureRandom(   )))

            val cAlpha = public.kv.clone().mul(verifier, alpha)
            val a = verifier.encWithNonce(beta, rho).add(verifier, cAlpha)

            val e = public.aux.commit(alpha, gamma)
            val s = public.aux.commit(private.x, m)
            val f = public.aux.commit(beta, delta)
            val t = public.aux.commit(private.y, mu)

            val commitment = Commitment(a, prover.encWithNonce(alpha, rhoX), prover.encWithNonce(beta, rhoY), e, s, f, t)

            val eVal = challenge(hash, group, public, commitment)!!

            val z1 = private.x.add(eVal.multiply(alpha))
            val z2 = private.y.add(eVal.multiply(beta))
            val z3 = gamma.add(eVal.multiply(m))
            val z4 = delta.add(eVal.multiply(mu))
            val w = private.s.modPow(eVal, verifier.modulus()).multiply(rho).mod(verifier.modulus())
            val wx = private.rx.modPow(eVal, prover.modulus()).multiply(rhoX).mod(prover.modulus())
            val wy = private.r.modPow(eVal, prover.modulus()).multiply(rhoY).mod(prover.modulus())

            return Proof(group, commitment, z1, z2, z3, z4, w, wx, wy)
        }
    }
}
