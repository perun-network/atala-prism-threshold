package perun_network.ecdsa_threshold.zk.enc

import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.math.curve.Curve
import perun_network.ecdsa_threshold.math.isInIntervalLEps
import perun_network.ecdsa_threshold.math.isValidBigModN
import perun_network.ecdsa_threshold.math.sample.*
import perun_network.ecdsa_threshold.protocols.cmp.paillier.CipherText
import perun_network.ecdsa_threshold.protocols.cmp.paillier.PublicKey
import perun_network.ecdsa_threshold.protocols.cmp.pedersen.Parameters
import java.math.BigInteger
import java.security.SecureRandom

data class Public(
    val k: CipherText, // K = Enc₀(k;ρ)
    val prover: PublicKey,
    val aux: Parameters
)

data class Private(
    val k: BigInteger,   // K = k ∈ 2ˡ = Dec₀(K)
    val rho: BigInteger  // Rho = ρ
)

data class Commitment(
    val s: BigInteger,  // S = sᵏtᵘ
    val a: CipherText, // A = Enc₀ (α, r)
    val c: BigInteger  // C = sᵃtᵍ
)

data class Proof(
    val commitment: Commitment,
    val z1: BigInteger,  // Z₁ = α + e⋅k
    val z2: BigInteger,  // Z₂ = r ⋅ ρᵉ mod N₀
    val z3: BigInteger   // Z₃ = γ + e⋅μ
) {

    fun isValid(public: Public): Boolean {
        return public.prover.validateCiphertexts(commitment.a) &&
                isValidBigModN(public.prover.modulus(), z2)
    }

    companion object {
        fun newProof(group: Curve, hash: Hash, public: Public, private: Private): Proof {
            val n = public.prover.modulus()
            val nModulus = public.prover.modulus()

            val alpha = intervalLEps(SecureRandomInputStream(SecureRandom()))
            val r = unitModN(SecureRandomInputStream(SecureRandom()), n)
            val mu = intervalLN(SecureRandomInputStream(SecureRandom()))
            val gamma = intervalLEpsN(SecureRandomInputStream(SecureRandom()))

            val a = public.prover.encWithNonce(alpha, r)

            val commitment = Commitment(
                s = public.aux.commit(private.k, mu),
                a = a,
                c = public.aux.commit(alpha, gamma)
            )

            val e = challenge(hash, group, public, commitment)

            val z1 = e.multiply(private.k).add(alpha)

            val z2 = private.rho.modPow(e, nModulus).apply {
                multiply(r).mod(n)
            }

            val z3 = e.multiply(mu).add(gamma)

            return Proof(commitment, z1, z2, z3)
        }

        private fun challenge(hash: Hash, group: Curve, public: Public, commitment: Commitment): BigInteger {
            hash.writeAny(public.aux, public.prover, public.k, commitment.s, commitment.a, commitment.c)
            return intervalScalar(hash.digest().inputStream(), group)
        }
    }

    fun verify(group: Curve, hash: Hash, public: Public): Boolean {
        if (!isValid(public)) return false

        val prover = public.prover

        if (!isInIntervalLEps(z1)) return false

        val e = challenge(hash, group, public, commitment)

        if (!public.aux.verify(z1, z3, e, commitment.c, commitment.s)) return false

        val lhs = prover.encWithNonce(z1, z2)
        val rhs = public.k.clone().mul(prover, e).add(prover, commitment.a)

        return lhs == rhs
    }
}