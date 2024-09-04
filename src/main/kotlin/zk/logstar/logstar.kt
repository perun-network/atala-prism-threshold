package perun_network.ecdsa_threshold.zk.logstar

import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.math.curve.Curve
import perun_network.ecdsa_threshold.math.curve.Point
import perun_network.ecdsa_threshold.math.curve.makeInt
import perun_network.ecdsa_threshold.math.*
import perun_network.ecdsa_threshold.math.sample.*
import perun_network.ecdsa_threshold.math.sample.intervalScalar
import perun_network.ecdsa_threshold.protocols.cmp.paillier.CipherText
import perun_network.ecdsa_threshold.protocols.cmp.paillier.PublicKey
import perun_network.ecdsa_threshold.protocols.cmp.pedersen.Parameters
import java.math.BigInteger
import java.security.SecureRandom

data class Public(
    val c: CipherText,          // Encryption of x under the prover's key
    val x: Point,               // X = x⋅G
    var g: Point?,              // Base point of the curve, use default if null
    val prover: PublicKey,
    val aux: Parameters
)

data class Private(
    val x: BigInteger,                 // Plaintext of C and discrete log of X
    val rho: BigInteger                // Nonce used to encrypt C
)

data class Commitment(
    val s: BigInteger?,                 // S = sˣ tᵘ (mod N)
    val a: CipherText?,          // A = Enc₀(alpha; r)
    val y: Point?,               // Y = α⋅G
    val d: BigInteger?                  // D = sᵃ tᵍ (mod N)
)

class Proof(
    private val group: Curve,
    private val commitment: Commitment,
    private val z1: BigInteger?,        // Z1 = α + e x
    private val z2: BigInteger?,        // Z2 = r ρᵉ mod N
    private val z3: BigInteger?         // Z3 = γ + e μ
) {

    fun isValid(public: Public): Boolean {
        if (!public.prover.validateCiphertexts(commitment.a!!)) return false
        if (commitment.y!!.isIdentity()) return false
        if (!isValidBigModN(public.prover.modulus(), z2)) return false
        return true
    }

    companion object {
        fun newProof(group: Curve, hash: Hash, public: Public, private: Private): Proof {
            val n = public.prover.modulus()
            val nModulus = public.prover.modulus()

            public.g = public.g ?: group.newBasePoint()

            val alpha = intervalLEps(SecureRandomInputStream(SecureRandom()))
            val r = unitModN(SecureRandomInputStream(SecureRandom()), n)
            val mu = intervalLN(SecureRandomInputStream(SecureRandom()))
            val gamma = intervalLEpsN(SecureRandomInputStream(SecureRandom()))

            val commitment = Commitment(
                a = public.prover.encWithNonce(alpha, r),
                y = group.newScalar().setNat(alpha.mod(group.order())).act(public.g!!),
                s = public.aux.commit(private.x, mu),
                d = public.aux.commit(alpha, gamma)
            )

            val (e, _) = challenge(hash, group, public, commitment)

            val z1 = e.multiply(private.x).add(alpha)

            val z2 = private.rho.modPow(e, nModulus).multiply(r).mod(n)

            val z3 = e.multiply(mu).add(gamma)

            return Proof(group, commitment, z1, z2, z3)
        }

        fun challenge(hash: Hash, group: Curve, public: Public, commitment: Commitment): Pair<BigInteger, Exception?> {
            hash.writeAny(
                public.aux, public.prover, public.c, public.x, public.g!!,
                commitment.s!!, commitment.a!!, commitment.y!!, commitment.d!!
            )
            val e = intervalScalar(hash.digest().inputStream(), group)
            return Pair(e, null)
        }

        fun empty(group: Curve): Proof {
            return Proof(group, Commitment(null, null, group.newPoint(), null), null, null, null)
        }
    }

    fun verify(hash: Hash, public: Public): Boolean {
        if (!isValid(public)) return false

        public.g = public.g ?: group.newBasePoint()

        if (!isInIntervalLEps(z1!!)) return false

        val (e, err) = challenge(hash, group, public, commitment)
        if (err != null) return false

        if (!public.aux.verify(z1, z3!!, e, commitment.d!!, commitment.s!!)) return false

        val lhs = public.prover.encWithNonce(z1, z2!!)
        val rhs = public.c.clone().mul(public.prover, e).add(public.prover, commitment.a)
        if (lhs != rhs) return false

        val lhsPoint = group.newScalar().setNat(z1.mod(group.order())).act(public.g!!)
        val rhsPoint = group.newScalar().setNat(e.mod(group.order())).act(public.x).add(commitment.y!!)
        if (!lhsPoint.equals(rhsPoint)) return false

        return true
    }
}