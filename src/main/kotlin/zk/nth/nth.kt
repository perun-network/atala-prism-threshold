package perun_network.ecdsa_threshold.zk.nth

import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.math.isValidBigModN
import perun_network.ecdsa_threshold.math.sample.SecureRandomInputStream
import perun_network.ecdsa_threshold.math.sample.intervalL
import perun_network.ecdsa_threshold.math.sample.unitModN
import perun_network.ecdsa_threshold.protocols.cmp.paillier.PublicKey
import java.math.BigInteger
import java.security.SecureRandom

data class Public(
    val n: PublicKey,           // N
    val r: BigInteger              // R = r = ρᴺ (mod N²)
)

data class Private(
    val rho: BigInteger            // Rho = ρ
)

data class Commitment(
    val a: BigInteger              // A = αᴺ (mod N²)
)

data class Proof(
    val commitment: Commitment,
    val z: BigInteger              // Z = αρᴺ (mod N²)
) {

    fun isValid(public: Public): Boolean {
        return isValidBigModN(public.n.modulus(), z) && isValidBigModN(public.n.modulusSquared(), commitment.a)
    }

    companion object {
        fun newProof(hash: Hash, public: Public, private: Private): Proof {
            val n = public.n.modulus()
            val alpha = unitModN(SecureRandomInputStream(SecureRandom()), n)  // α ← ℤₙˣ
            val a = alpha.modPow(n, public.n.modulusSquared()) // A = αⁿ (mod n²)

            val commitment = Commitment(a)
            val e = challenge(hash, public, commitment)

            var z = private.rho.modPow(e, public.n.modulus()) // Z = αρᵉ (mod N)
            z= z.multiply( alpha).mod(n)

            return Proof(commitment, z)
        }

        private fun challenge(hash: Hash, public: Public, commitment: Commitment): BigInteger {
            hash.writeAny(public.n, public.r, commitment.a)
            return intervalL(hash.digest().inputStream())
        }

        fun empty(): Proof {
            return Proof(Commitment(BigInteger.ZERO), BigInteger.ZERO)
        }
    }

    fun verify(hash: Hash, public: Public): Boolean {
        if (!isValid(public)) return false

        val e = challenge(hash, public, commitment)

        val nSquared = public.n.modulusSquared()
        val lhs = z.modPow(public.n.modulus(), nSquared)  // lhs = Zⁿ (mod N²)
        var rhs = public.r.modPow( e, nSquared)      // rhs = Rᵉ (mod N²)
        rhs = rhs.multiply(commitment.a).mod(nSquared)

        return lhs == rhs
    }
}