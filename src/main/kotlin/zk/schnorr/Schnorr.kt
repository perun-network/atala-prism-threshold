package perun_network.ecdsa_threshold.zk.schnorr

import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.hash.WriterToWithDomain
import perun_network.ecdsa_threshold.math.curve.*
import perun_network.ecdsa_threshold.math.sample.SecureRandomInputStream
import perun_network.ecdsa_threshold.math.sample.scalar
import java.io.ByteArrayInputStream
import java.io.OutputStream
import java.security.SecureRandom

class Commitment(val C: Point) : WriterToWithDomain {
    override fun writeTo(outputStream: OutputStream): Long {
        val data = C.marshalBinary() // Assuming `toByteArray` is a method to serialize the point
        outputStream.write(data)
        return data.size.toLong()
    }

    override fun domain(): String {
        return "Schnorr Commitment"
    }

    fun isValid(): Boolean {
        return !C.isIdentity() // Assuming `isIdentity` checks if the point is the identity element
    }
}

class Response(private val group: Curve, val Z: Scalar) {
    fun isValid(): Boolean {
        return !Z.isZero() // Assuming `isZero` checks if the scalar is zero
    }

    fun verify(hash: Hash, public: Point, commitment: Commitment, gen: Point?): Boolean {
        val actualGen = gen ?: public.curve().newBasePoint()
        if (!isValid() || public.isIdentity()) return false

        val e = challenge(hash, group, commitment, public, actualGen)
        val lhs = Z.act(actualGen)
        val rhs = e.act(public).add(commitment.C)

        return lhs == rhs
    }
}

class Proof(val C: Commitment, val Z: Response) {
    fun isValid(): Boolean {
        return Z.isValid() && C.isValid()
    }

    fun verify(hash: Hash, public: Point, gen: Point?): Boolean {
        return if (isValid()) {
            Z.verify(hash, public, C, gen)
        } else {
            false
        }
    }
}

fun newProof(hash: Hash, public: Point, private: Scalar, gen: Point): Proof {
    val group = private.curve()
    val a = newRandomness(SecureRandom(), group, gen)
    val z = a.prove(hash, public, private, gen)
    return Proof(
        C = a.commitment(),
        Z = z
    )
}

fun newRandomness(random: SecureRandom, group: Curve, gen: Point?): Randomness {
    val actualGen = gen ?: group.newBasePoint()
    val a = scalar(SecureRandomInputStream(random), group)
    return Randomness(a, Commitment(a.act(actualGen)))
}

fun challenge(hash: Hash, group: Curve, commitment: Commitment, public: Point, gen: Point): Scalar {
    hash.writeAny(commitment.C, public, gen)
    return scalar(ByteArrayInputStream(hash.digest()), group) // Assuming `digest` gives us a random seed
}

class Randomness(val a: Scalar, private val commitment: Commitment) {
    fun prove(hash: Hash, public: Point, secret: Scalar, gen: Point?): Response {
        val actualGen = gen ?: public.curve().newBasePoint()
        if (public.isIdentity() || secret.isZero()) return emptyResponse(public.curve())

        val e = challenge(hash, public.curve(), commitment, public, actualGen)
        val es = e.mul(secret)
        val z = es.add(a)

        return Response(public.curve(), z)
    }

    fun commitment(): Commitment {
        return commitment
    }
}

fun emptyProof(group: Curve): Proof {
    return Proof(
        C = Commitment(group.newPoint()),
        Z = Response(group, group.newScalar())
    )
}

fun emptyResponse(group: Curve): Response {
    return Response(group, group.newScalar())
}

fun emptyCommitment(group: Curve): Commitment {
    return Commitment(group.newPoint())
}
