package perun_network.ecdsa_threshold.zero_knowledge.fac

import perun_network.ecdsa_threshold.math.*
import perun_network.ecdsa_threshold.pedersen.PedersenParameters
import java.math.BigInteger
import java.security.MessageDigest

// Public parameters
data class FacPublic(
    val n: BigInteger,
    val aux: PedersenParameters
)

// Private key
data class FacPrivate(
    val p: BigInteger,
    val q: BigInteger
)

// Commitment structure
data class FacCommitment(
    val p: BigInteger,
    val q: BigInteger,
    val a: BigInteger,
    val b: BigInteger,
    val t: BigInteger
)

// Proof structure
data class FacProof(
    val comm: FacCommitment,
    val sigma: BigInteger,
    val z1: BigInteger,
    val z2: BigInteger,
    val w1: BigInteger,
    val w2: BigInteger,
    val v: BigInteger
) {
    internal fun verify(id: Int, rid: ByteArray, public : FacPublic) : Boolean {
        val e = challenge(id, rid, public, comm) ?: return false

        val n0 = public.n
        val n = public.aux.n

        if (!public.aux.verifyCommit(z1, w1, e, comm.a, comm.p)) return false
        if (!public.aux.verifyCommit(z2, w2, e, comm.b, comm.q)) return false

        val r = public.aux.s
            .modPow(n0, n)
            .multiply(public.aux.t.modPow(sigma, n))
            .mod(n)

        val lhs = comm.q.modPow(z1, n)
            .multiply(public.aux.t.modPow(v, n))
            .mod(n)

        val rhs = r.modPow(e, n)
            .multiply(comm.t)
            .mod(n)

        if (lhs != rhs) return false

        // Ensure z1 and z2 are within valid intervals
        return isInIntervalLEpsPlus1RootN(z1) && isInIntervalLEpsPlus1RootN(z2)
    }

    companion object {
        internal fun newProof(id: Int, rid: ByteArray, public: FacPublic, private: FacPrivate): FacProof {
            val n = public.aux.n

            // Random values for proof generation
            val alpha = sampleLEpsRootN()
            val beta = sampleLEpsRootN()
            val mu = sampleLN()
            val nu = sampleLN()
            val sigma = sampleLN2()
            val r = sampleLEpsN2()
            val x = sampleLEpsN()
            val y = sampleLEpsN()

            val pInt = private.p
            val qInt = private.q

            val pCommit = public.aux.calculateCommit(pInt, mu)
            val qCommit = public.aux.calculateCommit(qInt, nu)
            val aCommit = public.aux.calculateCommit(alpha, x)
            val bCommit = public.aux.calculateCommit(beta, y)

            val tCommit = qCommit.modPow(alpha, n)
                .multiply(public.aux.t.modPow(r, n))
                .mod(n)

            val comm = FacCommitment(pCommit, qCommit, aCommit, bCommit, tCommit)

            // Generate challenge
            val e = challenge(id, rid, public, comm)

            // Compute z1, z2, w1, w2, and v
            val z1 = e.multiply(pInt).negate().add(alpha)
            val z2 = e.multiply(qInt).negate().add(beta)
            val w1 = e.multiply(mu).negate().add(x)
            val w2 = e.multiply(nu).negate().add(y)

            val sigmaHat = nu.multiply(pInt).negate().add(sigma)
            val v = e.multiply(sigmaHat).negate().add(r)

            return FacProof(comm, sigma, z1, z2, w1, w2, v)
        }
    }
}

fun challenge(id: Int, rid: ByteArray , publicKey: FacPublic, commitment: FacCommitment): BigInteger {
    // Initialize a MessageDigest for SHA-256
    val hash = MessageDigest.getInstance("SHA-256")
    hash.update(id.toByte())
    hash.update(rid)
    hash.update(publicKey.n.toByteArray())
    hash.update(publicKey.aux.toByteArray())
    hash.update(commitment.p.toByteArray())
    hash.update(commitment.q.toByteArray())
    hash.update(commitment.a.toByteArray())
    hash.update(commitment.b.toByteArray())
    hash.update(commitment.t.toByteArray())

    return sampleNeg(hash.digest().inputStream(), L)
}