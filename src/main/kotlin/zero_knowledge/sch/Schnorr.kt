package perun_network.ecdsa_threshold.zero_knowledge.sch

import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.ecdsa.secp256k1Order
import perun_network.ecdsa_threshold.math.sampleScalar
import java.math.BigInteger

data class SchnorrPublic (
    val X : Point,
)

data class SchnorrPrivate (
    val x : Scalar
)

data class SchnorrCommitment(
    val alpha: Scalar,
    val A: Point,
) {
    companion object {
        internal fun newCommitment() : SchnorrCommitment {
            val alpha = sampleScalar()
            return SchnorrCommitment(alpha, alpha.actOnBase())
        }
    }
}

data class SchnorrProof(
    val z: Scalar,
    val A: Point,
) {
    private fun isValid(): Boolean {
        if (z.isZero() || A.isIdentity()) {
            return false
        }
        return true
    }

    fun verify(id: Int, public: SchnorrPublic) : Boolean {
        if (!isValid()) return false

        val e = challenge(id, public, A)

        // Check g^z = A · X^e
        if (z.actOnBase() != Scalar.scalarFromBigInteger(e).act(public.X).add(A)) {
            return false
        }

        return true
    }

    companion object {
        internal fun newProof(id: Int, public: SchnorrPublic, private: SchnorrPrivate): SchnorrProof {
            val alpha = sampleScalar()

            val A = alpha.actOnBase()

            val e = challenge(id, public, A)

            val z = alpha.add(private.x.multiply(Scalar.scalarFromBigInteger(e)))
            return SchnorrProof(z, A)
        }

        internal fun newProofWithCommitment(id: Int, public: SchnorrPublic, private: SchnorrPrivate, commitment: SchnorrCommitment): SchnorrProof {
            val e = challenge(id, public, commitment.A)
            val z = commitment.alpha.add(private.x.multiply(Scalar.scalarFromBigInteger(e)))

            return SchnorrProof(z, commitment.A)
        }

        private fun challenge(id: Int, public: SchnorrPublic, A: Point): BigInteger {
            // Collect relevant parts to form the challenge
            val inputs = listOf<BigInteger>(
                public.X.x,
                public.X.y,
                A.x,
                A.y,
                BigInteger.valueOf(id.toLong())
            )
            return inputs.fold(BigInteger.ZERO) { acc, value -> acc.add(value).mod(secp256k1Order()) }.mod(
                secp256k1Order()
            )
        }
    }
}
