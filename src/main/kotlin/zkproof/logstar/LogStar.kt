package perun_network.ecdsa_threshold.zkproof.logstar

import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.ecdsa.newBasePoint
import perun_network.ecdsa_threshold.ecdsa.secp256k1Order
import perun_network.ecdsa_threshold.math.*
import perun_network.ecdsa_threshold.paillier.PaillierCipherText
import perun_network.ecdsa_threshold.paillier.PaillierPublic
import perun_network.ecdsa_threshold.pedersen.PedersenParameters
import java.math.BigInteger

data class LogStarPublic(
    // C = Enc₀(x;ρ)
    // Encryption of x under the prover's key
    val C : PaillierCipherText,
    // X = G^x
    val X : Point,

    val n0 : PaillierPublic,
    val aux    : PedersenParameters
)

data class LogStarPrivate(
    // X is the plaintext of C and the discrete log of X.
    val x: BigInteger,
    // Rho = ρ is nonce used to encrypt C.
    val rho : BigInteger
)

data class LogStarCommitment(
    val S: BigInteger,                  // S = sˣ tᵘ (mod N)
    val A: PaillierCipherText,          // A = Enc₀(alpha; r)
    val Y: Point,                       // Y = G^a
    val D: BigInteger                  // D = sᵃ tᵍ (mod N)
)

class LogStarProof(
    private val commitment: LogStarCommitment,
    private val z1: BigInteger,        // z1 = α + e x
    private val z2: BigInteger,        // z2 = r ρᵉ mod N
    private val z3: BigInteger         // z3 = γ + e μ
) {

    fun isValid(public: LogStarPublic): Boolean {
        if (!public.n0.validateCiphertexts(commitment.A)) return false
        if (commitment.Y.isIdentity()) return false
        if (!isValidBigModN(public.n0.n, z2)) return false
        return true
    }

    companion object {
        fun newProof(id: Int, public: LogStarPublic, private: LogStarPrivate): LogStarProof {
            val n = public.n0.n

            val g = newBasePoint()

            val alpha = sampleLEps()
            val r = sampleUnitModN(n)
            val mu = sampleLN()
            val gamma = sampleLEpsN()

            val commitment = LogStarCommitment(
                A = public.n0.encWithNonce(alpha, r),
                Y = Scalar(alpha.mod(secp256k1Order())).act(g),
                S = public.aux.commit(private.x, mu),
                D = public.aux.commit(alpha, gamma)
            )

            val e = challenge(id, public, commitment)

            val z1 = e.multiply(private.x).add(alpha)

            val z2 = private.rho.modPow(e, n).multiply(r).mod(n)

            val z3 = e.multiply(mu).add(gamma)

            return LogStarProof(commitment, z1, z2, z3)
        }

        fun challenge(id: Int, public: LogStarPublic, commitment: LogStarCommitment): BigInteger {
            // Collect relevant parts to form the challenge
            val inputs = listOf<BigInteger>(
                public.aux.n,
                public.aux.s,
                public.aux.t,
                public.n0.n,
                public.C.value(),
                public.X.x,
                public.X.y,
                commitment.S,
                commitment.A.value(),
                commitment.Y.x,
                commitment.Y.y,
                commitment.D,
                BigInteger.valueOf(id.toLong())
            )
            return inputs.fold(BigInteger.ZERO) { acc, value -> acc.add(value).mod(secp256k1Order()) }.mod(secp256k1Order())
        }
    }

    fun verify(id: Int, public: LogStarPublic): Boolean {
        if (!isValid(public)) return false

        val g = newBasePoint()

        if (!isInIntervalLEps(z1)) return false

        val e = challenge(id, public, commitment)

        if (!public.aux.verify(z1, z3, e, commitment.D, commitment.S)) return false

        val lhs = public.n0.encWithNonce(z1, z2)
        val rhs = public.C.clone().modPowNSquared(public.n0, e).mul(public.n0, commitment.A)
        if (lhs != rhs) return false

        val lhsPoint = Scalar(z1.mod(secp256k1Order())).act(g)
        val rhsPoint = Scalar(e.mod(secp256k1Order())).act(public.X).add(commitment.Y)
        if (lhsPoint != rhsPoint) return false

        return true
    }
}