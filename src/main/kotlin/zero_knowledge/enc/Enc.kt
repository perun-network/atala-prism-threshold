package perun_network.ecdsa_threshold.zkproof.enc

import perun_network.ecdsa_threshold.ecdsa.secp256k1Order
import perun_network.ecdsa_threshold.math.*
import perun_network.ecdsa_threshold.paillier.PaillierCipherText
import perun_network.ecdsa_threshold.paillier.PaillierPublic
import perun_network.ecdsa_threshold.pedersen.PedersenParameters
import java.math.BigInteger

data class EncPublic(
    val K: PaillierCipherText,
    val n0: PaillierPublic,
    val aux: PedersenParameters
)

data class EncPrivate(
    val k: BigInteger,   // k = k ∈ 2ˡ = Dec₀(K)
    val rho: BigInteger  // rho = ρ
)

data class EncCommitment(
    val S: BigInteger,  // S = sᵏtᵘ
    val A: PaillierCipherText, // A = Enc₀ (α, r)
    val C: BigInteger  // C = sᵃtᵍ
)

data class EncProof(
    val commitment: EncCommitment,
    val z1: BigInteger,  // z₁ = α + e⋅k
    val z2: BigInteger,  // z₂ = r ⋅ ρᵉ mod N₀
    val z3: BigInteger   // z₃ = γ + e⋅μ
) {

    fun isValid(public: EncPublic): Boolean {
        return public.n0.validateCiphertexts(commitment.A) &&
                isValidBigModN(public.n0.n, z2)
    }

    companion object {
        fun newProof(id: Int, public: EncPublic, private: EncPrivate): EncProof {
            val n = public.n0.n

            val alpha = sampleLEps()
            val r = sampleUnitModN(n)
            val mu = sampleLN()
            val gamma = sampleLEpsN()

            val a = public.n0.encWithNonce(alpha, r)

            val commitment = EncCommitment(
                S = public.aux.commit(private.k, mu),
                A = a,
                C = public.aux.commit(alpha, gamma)
            )

            val e = challenge(id, public, commitment)

            val z1 = e.multiply(private.k).add(alpha)

            val z2 = private.rho.modPow(e, n).apply {
                multiply(r).mod(n)
            }

            val z3 = e.multiply(mu).add(gamma)
            return EncProof(commitment, z1, z2, z3)
        }

        private fun challenge(id: Int, public: EncPublic, commitment: EncCommitment): BigInteger {
            // Collect relevant parts to form the challenge
            val inputs = listOf<BigInteger>(
                public.n0.n,
                public.K.c,
                commitment.S,
                commitment.A.c,
                commitment.C,
                BigInteger.valueOf(id.toLong())
            )
            return inputs.fold(BigInteger.ZERO) { acc, value -> acc.add(value).mod(secp256k1Order()) }.mod(secp256k1Order())
        }
    }

    fun verify(id: Int, public: EncPublic): Boolean {
        if (!isValid(public)) return false

        val prover = public.n0

        if (!isInIntervalLEps(z1)) return false

        val e = challenge(id, public, commitment)

        if (!public.aux.verify(z1, z3, e, commitment.C, commitment.S)) return false

        val lhs = prover.encWithNonce(z1, z2)
        val rhs = public.K.modPowNSquared(prover, e).modMulNSquared(prover, commitment.A)

        return lhs == rhs
    }
}