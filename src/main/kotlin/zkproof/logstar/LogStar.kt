package perun_network.ecdsa_threshold.zkproof.logstar

import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.ecdsa.newBasePoint
import perun_network.ecdsa_threshold.ecdsa.secp256k1Order
import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.math.*
import perun_network.ecdsa_threshold.paillier.PaillierCipherText
import perun_network.ecdsa_threshold.paillier.PaillierPublic
import perun_network.ecdsa_threshold.pedersen.PedersenParameters
import java.math.BigInteger

data class LogStarPublic(
    // C = Enc₀(x;ρ)
    // Encryption of x under the prover's key
    val c : PaillierCipherText,
    // X = x.G
    val x : Point,
    // G is the base point of the curve.
    // If G = nil, the default base point is used.
    var g : Point?,

    val prover : PaillierPublic,
    val aux    : PedersenParameters
)

data class LogStarPrivate(
    // X is the plaintext of C and the discrete log of X.
    val x: BigInteger,
    // Rho = ρ is nonce used to encrypt C.
    val rho : BigInteger
)

data class LogStarCommitment(
    val s: BigInteger,                  // S = sˣ tᵘ (mod N)
    val a: PaillierCipherText,          // A = Enc₀(alpha; r)
    val y: Point,                       // Y = α⋅G
    val d: BigInteger                  // D = sᵃ tᵍ (mod N)
)

class LogStarProof(
    private val commitment: LogStarCommitment,
    private val z1: BigInteger,        // Z1 = α + e x
    private val z2: BigInteger,        // Z2 = r ρᵉ mod N
    private val z3: BigInteger         // Z3 = γ + e μ
) {

    fun isValid(public: LogStarPublic): Boolean {
        if (!public.prover.validateCiphertexts(commitment.a)) return false
        if (commitment.y.isIdentity()) return false
        if (!isValidBigModN(public.prover.n, z2)) return false
        return true
    }

    companion object {
        fun newProof(hash: Hash, public: LogStarPublic, private: LogStarPrivate): LogStarProof {
            val n = public.prover.n

            public.g = public.g ?: newBasePoint()

            val alpha = intervalLEps()
            val r = unitModN(n)
            val mu = intervalLN()
            val gamma = intervalLEpsN()

            val commitment = LogStarCommitment(
                a = public.prover.encWithNonce(alpha, r),
                y = Scalar(alpha.mod(secp256k1Order())).act(public.g!!),
                s = public.aux.commit(private.x, mu),
                d = public.aux.commit(alpha, gamma)
            )

            val e = challenge(hash, public, commitment)

            val z1 = e.multiply(private.x).add(alpha)

            val z2 = private.rho.modPow(e, n).multiply(r).mod(n)

            val z3 = e.multiply(mu).add(gamma)

            return LogStarProof(commitment, z1, z2, z3)
        }

        fun challenge(hash: Hash, public: LogStarPublic, commitment: LogStarCommitment): BigInteger {
            hash.writeAny(
                public.aux, public.prover, public.c, public.x, public.g!!,
                commitment.s, commitment.a, commitment.y, commitment.d
            )
            val e = intervalScalar(hash.digest().inputStream())
            return e
        }
    }

    fun verify(hash: Hash, public: LogStarPublic): Boolean {
        if (!isValid(public)) return false

        public.g = public.g ?: newBasePoint()

        if (!isInIntervalLEps(z1)) return false

        val e = challenge(hash, public, commitment)

        if (!public.aux.verify(z1, z3, e, commitment.d, commitment.s)) return false

        val lhs = public.prover.encWithNonce(z1, z2)
        val rhs = public.c.clone().mul(public.prover, e).add(public.prover, commitment.a)
        if (lhs != rhs) return false

        val lhsPoint = Scalar(z1.mod(secp256k1Order())).act(public.g!!)
        val rhsPoint = Scalar(e.mod(secp256k1Order())).act(public.x).add(commitment.y)
        if (lhsPoint != rhsPoint) return false

        return true
    }
}