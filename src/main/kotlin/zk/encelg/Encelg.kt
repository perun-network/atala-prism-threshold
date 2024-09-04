package perun_network.ecdsa_threshold.zk.encelg

import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.math.curve.Curve
import perun_network.ecdsa_threshold.math.curve.Point
import perun_network.ecdsa_threshold.math.curve.Scalar
import perun_network.ecdsa_threshold.math.isValidBigModN
import perun_network.ecdsa_threshold.math.sample.SecureRandomInputStream
import perun_network.ecdsa_threshold.math.sample.*
import perun_network.ecdsa_threshold.protocols.cmp.paillier.CipherText
import perun_network.ecdsa_threshold.protocols.cmp.paillier.PublicKey
import perun_network.ecdsa_threshold.protocols.cmp.pedersen.Parameters
import java.math.BigInteger
import java.security.SecureRandom

data class Public (
    val c: CipherText,  // C = Enc(x;ρ)
    val a: Point,               // A = a⋅G
    val b: Point,               // B = b⋅G
    val x: Point,               // X = (ab+x)⋅G
    val prover: PublicKey,
    val aux: Parameters
)

data class Private (
    val x: BigInteger,         // X = x = Dec(C)
    val rho: BigInteger,       // Rho = ρ = Nonce(C)
    val a: Scalar,              // A = a
    val b: Scalar               // B = b
)


data class Commitment(
    val s: BigInteger?,         // S = sˣtᵘ
    val d: CipherText?,          // D = Enc(α, r)
    val y: Point,               // Y = β⋅A+α⋅G
    val z: Point,               // Z = β⋅G
    val t: BigInteger?          // T = sᵃtᵍ
)

class Proof(
    private val group: Curve,
    private val commitment: Commitment?,
    private val z1: BigInteger?,    // Z1 = z₁ = α + ex
    private val w: Scalar,          // W = w = β + eb (mod q)
    private val z2: BigInteger?,    // Z2 = z₂ = r⋅ρᵉ (mod N₀)
    private val z3: BigInteger?     // Z3 = z₃ = γ + eμ
) {

    fun isValid(public: Public): Boolean {
        if (w.isZero() || commitment!!.y.isIdentity() || commitment.z.isIdentity()) {
            return false
        }
        if (!public.prover.validateCiphertexts(commitment.d!!)) {
            return false
        }
        if (!isValidBigModN(public.prover.modulus(), z2)) {
            return false
        }
        return true
    }

    fun verify(hash: Hash, public: Public): Boolean {
        if (!isValid(public)) {
            return false
        }

        val prover = public.prover
        val e = challenge(hash, group, public, commitment!!) ?: return false
        val q = group.order()
        val eScalar = group.newScalar().setNat(e.mod(q))

        // Check Enc(z₁;z₂) == (e ⊙ C) ⊕ D
        val lhs = prover.encWithNonce(z1!!, z2!!)
        val rhs = public.c.clone().mul(prover, e).add(prover, commitment.d)
        if (!lhs.equals(rhs)) {
            return false
        }

        // Check w⋅A+z₁⋅G == Y+e⋅X
        val lhsWZ1 = group.newScalar().setNat(z1.mod(q)).actOnBase().add(w.act(public.a))
        val rhsYEX = eScalar.act(public.x).add(commitment.y)
        if (!lhsWZ1.equals(rhsYEX)) {
            return false
        }

        // Check w⋅G == Z+e⋅B
        val lhsWG = w.actOnBase()
        val rhsZE = eScalar.act(public.b).add(commitment.z)
        if (!lhsWG.equals(rhsZE)) {
            return false
        }

        if (!public.aux.verify(z1, z3!!, e, commitment.t!!, commitment.s!!)) {
            return false
        }

        return true
    }

    companion object {
        fun newProof(group: Curve, hash: Hash, public: Public, private: Private): Proof {
            val n = public.prover.modulus()
            val nModulus = public.prover.modulus()

            val alpha = intervalLEps(SecureRandomInputStream(SecureRandom()))
            val alphaScalar = group.newScalar().setNat(alpha.mod(group.order()))
            val mu = intervalLN(SecureRandomInputStream(SecureRandom()))
            val r = unitModN(SecureRandomInputStream(SecureRandom()), n)
            val beta = scalar(SecureRandomInputStream(SecureRandom()), group)
            val gamma = intervalLEpsN(SecureRandomInputStream(SecureRandom()))

            val commitment = Commitment(
                s = public.aux.commit(private.x, mu),
                d = public.prover.encWithNonce(alpha, r),
                y = beta.act(public.a).add(alphaScalar.actOnBase()),
                z = beta.actOnBase(),
                t = public.aux.commit(alpha, gamma)
            )

            val e = challenge(hash, group, public, commitment)!!

            val z1 = e.multiply(private.x).add(alpha)

            val w = group.newScalar().setNat(e.mod(group.order())).mul(private.b).add(beta)

            val z2 = private.rho.modPow(e, nModulus).multiply(r).mod(n)

            val z3 = e.multiply(mu).add(gamma)
            return Proof(
                group = group,
                commitment = commitment,
                z1 = z1,
                w = w,
                z2 = z2,
                z3 = z3
            )
        }

        fun empty(group: Curve): Proof {
            return Proof(
                group = group,
                commitment = Commitment(
                    y = group.newPoint(),
                    z = group.newPoint(),
                    d = null,
                    s = null,
                    t = null
                ),
                w = group.newScalar(),
                z1 = null,
                z2 = null,
                z3 = null
            )
        }

        private fun challenge(hash: Hash, group: Curve, public: Public, commitment: Commitment): BigInteger? {
            hash.writeAny(
                public.aux, public.prover, public.c, public.a, public.b, public.x,
                commitment.s!!, commitment.d!!, commitment.y, commitment.z, commitment.t!!
            )
            return intervalScalar(hash.digest().inputStream(), group)
        }
    }
}