package perun_network.ecdsa_threshold.zk.elog

import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.internal.elgamal.Ciphertext
import perun_network.ecdsa_threshold.internal.elgamal.PublicKey
import perun_network.ecdsa_threshold.math.curve.Curve
import perun_network.ecdsa_threshold.math.curve.Point
import perun_network.ecdsa_threshold.math.curve.Scalar
import perun_network.ecdsa_threshold.math.sample.SecureRandomInputStream
import perun_network.ecdsa_threshold.math.sample.scalar
import java.security.SecureRandom

data class Public(
    val e: Ciphertext,       // E = (L=λ⋅G, M=y⋅G+λ⋅X)
    val elGamalPublic: Point, // ElGamalPublic = X
    val base: Point,         // Base = H
    val y: Point             // Y = y⋅H
)

data class Private(
    val y: Scalar,           // Y = y
    val lambda: Scalar       // Lambda = λ
)

data class Commitment(
    val a: Point,            // A = α⋅G
    val n: Point,            // N = m⋅G+α⋅X
    val b: Point             // B = m⋅H
)

class Proof(
    private val group: Curve,
    private val commitment: Commitment,
    private val z: Scalar,   // Z = α+eλ (mod q)
    private val u: Scalar    // U = m+ey (mod q)
) {

    fun isValid(public: Public): Boolean {
        return !(commitment.a.isIdentity() || commitment.n.isIdentity() || commitment.b.isIdentity() ||
                z.isZero() || u.isZero())
    }

    companion object {
        fun newProof(group: Curve, hash: Hash, public: Public, private: Private): Proof {
            val alpha = scalar(SecureRandomInputStream(SecureRandom()), group)
            val m = scalar(SecureRandomInputStream(SecureRandom()), group)

            val commitment = Commitment(
                a = alpha.actOnBase(),                                   // A = α⋅G
                n = m.actOnBase().add(alpha.act(public.elGamalPublic)),  // N = m⋅G+α⋅X
                b = m.act(public.base)                                   // B = m⋅H
            )

            val e = challenge(hash, group, public, commitment)

            val z = group.newScalar().set(e).mul(private.lambda).add(alpha) // Z = α+eλ (mod q)
            val u = group.newScalar().set(e).mul(private.y).add(m)          // U = m+ey (mod q)

            return Proof(group, commitment, z, u)
        }

        private fun challenge(hash: Hash, group: Curve, public: Public, commitment: Commitment): Scalar {
            hash.writeAny(public.e, public.elGamalPublic, public.y, public.base,
                commitment.a, commitment.n, commitment.b)
            return scalar(hash.digest().inputStream(), group)
        }

        fun empty(group: Curve): Proof {
            return Proof(
                group,
                Commitment(
                    a = group.newPoint(),
                    n = group.newPoint(),
                    b = group.newPoint()
                ),
                z = group.newScalar(),
                u = group.newScalar()
            )
        }
    }

    fun verify(hash: Hash, public: Public): Boolean {
        if (!isValid(public)) return false

        val e = challenge(hash, group, public, commitment)

        val lhsZ = z.actOnBase() // lhs = z⋅G
        val rhsZ = e.act(public.e.l).add(commitment.a) // rhs = A+e⋅L
        if (lhsZ != rhsZ) return false

        val lhsU = u.actOnBase().add(z.act(public.elGamalPublic)) // lhs = u⋅G+z⋅X
        val rhsU = e.act(public.e.m).add(commitment.n) // rhs = N+e⋅M
        if (lhsU != rhsU) return false

        val lhsB = u.act(public.base) // lhs = u⋅H
        val rhsB = e.act(public.y).add(commitment.b) // rhs = B+e⋅Y
        if (lhsB != rhsB) return false

        return true
    }
}