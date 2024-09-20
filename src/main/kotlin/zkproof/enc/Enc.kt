package perun_network.ecdsa_threshold.zkproof.enc

import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.math.*
import perun_network.ecdsa_threshold.paillier.PaillierCipherText
import perun_network.ecdsa_threshold.paillier.PaillierPublic
import perun_network.ecdsa_threshold.pedersen.PedersenParameters
import java.math.BigInteger

data class EncPublic(
    val k: PaillierCipherText, // K = Enc₀(k;ρ)
    val prover: PaillierPublic,
    val aux: PedersenParameters
)

data class EncPrivate(
    val k: BigInteger,   // K = k ∈ 2ˡ = Dec₀(K)
    val rho: BigInteger  // Rho = ρ
)

data class EncCommitment(
    val s: BigInteger,  // S = sᵏtᵘ
    val a: PaillierCipherText, // A = Enc₀ (α, r)
    val c: BigInteger  // C = sᵃtᵍ
)

data class EncProof(
    val commitment: EncCommitment,
    val z1: BigInteger,  // Z₁ = α + e⋅k
    val z2: BigInteger,  // Z₂ = r ⋅ ρᵉ mod N₀
    val z3: BigInteger   // Z₃ = γ + e⋅μ
) {

    fun isValid(public: EncPublic): Boolean {
        return public.prover.validateCiphertexts(commitment.a) &&
                isValidBigModN(public.prover.n, z2)
    }

    companion object {
        fun newProof(hash: Hash, public: EncPublic, private: EncPrivate): EncProof {
            val n = public.prover.n

            val alpha = intervalLEps()
            val r = unitModN(n)
            val mu = intervalLN()
            val gamma = intervalLEpsN()

            val a = public.prover.encWithNonce(alpha, r)

            val commitment = EncCommitment(
                s = public.aux.commit(private.k, mu),
                a = a,
                c = public.aux.commit(alpha, gamma)
            )

            val e = challenge(hash, public, commitment)

            val z1 = e.multiply(private.k).add(alpha)

            val z2 = private.rho.modPow(e, n).apply {
                multiply(r).mod(n)
            }

            val z3 = e.multiply(mu).add(gamma)

            return EncProof(commitment, z1, z2, z3)
        }

        private fun challenge(hash: Hash, public: EncPublic, commitment: EncCommitment): BigInteger {
            hash.writeAny(public.aux, public.prover, public.k, commitment.s, commitment.a, commitment.c)
            return intervalScalar(hash.digest().inputStream())
        }
    }

    fun verify(hash: Hash, public: EncPublic): Boolean {
        if (!isValid(public)) return false

        val prover = public.prover

        if (!isInIntervalLEps(z1)) return false

        val e = challenge(hash, public, commitment)

        if (!public.aux.verify(z1, z3, e, commitment.c, commitment.s)) return false

        val lhs = prover.encWithNonce(z1, z2)
        val rhs = public.k.clone().mul(prover, e).add(prover, commitment.a)

        return lhs == rhs
    }
}