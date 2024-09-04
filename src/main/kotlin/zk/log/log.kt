package perun_network.ecdsa_threshold.zk.log

import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.math.curve.Curve
import perun_network.ecdsa_threshold.math.curve.Point
import perun_network.ecdsa_threshold.math.curve.Scalar
import perun_network.ecdsa_threshold.math.sample.SecureRandomInputStream
import perun_network.ecdsa_threshold.math.sample.scalar
import java.security.SecureRandom

data class Public(
    val h: Point, // H = b⋅G
    val x: Point, // X = a⋅G
    val y: Point  // Y = a⋅H
)

data class Private(
    val a: Scalar, // A = a
    val b: Scalar  // B = b
)

data class Commitment(
    val a: Point, // A = α⋅G
    val b: Point, // B = α⋅H
    val c: Point  // C = β⋅G
)

data class Proof(
    val group: Curve,
    val commitment: Commitment,
    val z1: Scalar, // Z1 = α + ea (mod q)
    val z2: Scalar  // Z2 = β + eb (mod q)
) {

    fun isValid(): Boolean {
        return !commitment.a.isIdentity() && !commitment.b.isIdentity() &&
                !commitment.c.isIdentity() && !z1.isZero() && !z2.isZero()
    }

    companion object {
        fun newProof(group: Curve, hash: Hash, public: Public, private: Private): Proof {
            val alpha = scalar(SecureRandomInputStream(SecureRandom()), group)
            val beta = scalar(SecureRandomInputStream(SecureRandom()), group)

            val commitment = Commitment(
                a = alpha.actOnBase(),   // A = α⋅G
                b = alpha.act(public.h), // B = α⋅H
                c = beta.actOnBase()     // C = β⋅G
            )

            val e = challenge(hash, group, public, commitment)

            val z1 = group.newScalar().set(e).mul(private.a).add(alpha) // Z₁ = α+ea (mod q)
            val z2 = group.newScalar().set(e).mul(private.b).add(beta)  // Z₂ = β+eb (mod q)

            return Proof(group, commitment, z1, z2)
        }

        private fun challenge(hash: Hash, group: Curve, public: Public, commitment: Commitment): Scalar {
            hash.writeAny(public.h, public.x, public.y, commitment.a, commitment.b, commitment.c)
            return scalar(hash.digest().inputStream(), group)
        }

        fun empty(group: Curve): Proof {
            return Proof(
                group,
                Commitment(
                    group.newPoint(),
                    group.newPoint(),
                    group.newPoint()
                ),
                group.newScalar(),
                group.newScalar()
            )
        }
    }

    fun verify(hash: Hash, public: Public): Boolean {
        if (!isValid()) return false

        val e = challenge(hash, group, public, commitment)

        val lhs1 = z1.actOnBase()         // lhs = z₁⋅G
        val rhs1 = e.act(public.x).add(commitment.a) // rhs = A + e⋅X
        if (!lhs1.equals(rhs1)) return false

        val lhs2 = z1.act(public.h)       // lhs = z₁⋅H
        val rhs2 = e.act(public.y).add(commitment.b) // rhs = B + e⋅Y
        if (!lhs2.equals(rhs2)) return false

        val lhs3 = z2.actOnBase()         // lhs = z₂⋅G
        val rhs3 = e.act(public.h).add(commitment.c) // rhs = C + e⋅H
        if (!lhs3.equals(rhs3)) return false

        return true
    }
}