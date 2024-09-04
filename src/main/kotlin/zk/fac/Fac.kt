package perun_network.ecdsa_threshold.zk.fac

import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.math.isInIntervalLEpsPlus1RootN
import perun_network.ecdsa_threshold.math.sample.*
import perun_network.ecdsa_threshold.protocols.cmp.pedersen.Parameters
import java.math.BigInteger
import java.security.SecureRandom

data class Public(
    val N: BigInteger,
    val Aux: Parameters
)

data class Private(
    val P: BigInteger,
    val Q: BigInteger,
)

data class Commitment(
    val P: BigInteger,
    val Q: BigInteger,
    val A: BigInteger,
    val B: BigInteger,
    val T: BigInteger
)

data class Proof(
    val Comm: Commitment,
    val Sigma: BigInteger,
    val Z1: BigInteger,
    val Z2: BigInteger,
    val W1: BigInteger,
    val W2: BigInteger,
    val V: BigInteger
)

fun newProof(private: Private, hash: Hash, public: Public): Proof {
    val random = SecureRandomInputStream(SecureRandom())

    // Figure 28, point 1
    val alpha = intervalLEpsRootN(random)
    val beta = intervalLEpsRootN(random)
    val mu = intervalLN(random)
    val nu = intervalLN(random)
    val sigma = intervalLN2(random)
    val r = intervalLEpsN(random)
    val x = intervalLEpsN(random)
    val y = intervalLEpsN(random)

    val pInt = private.P
    val qInt = private.Q
    val P = public.Aux.commit(pInt, mu)
    val Q = public.Aux.commit(qInt, nu)
    val A = public.Aux.commit(alpha, x)
    val B = public.Aux.commit(beta, y)
    var T = Q.modPow(alpha, public.Aux.n)
    T = T.multiply(public.Aux.t.modPow(r, public.Aux.n)).mod( public.Aux.n)

    val comm = Commitment(P, Q, A, B, T)

    // Figure 28, point 2
    val e = challenge(hash, public, comm)

    // Figure 28, point 3
    val z1 = e.multiply(pInt).negate().add(alpha)
    val z2 = e.multiply(qInt).negate().add(beta)
    val w1 = e.multiply(mu).negate().add(x)
    val w2 = e.multiply(nu).negate().add(y)
    val sigmaHat = nu.multiply(pInt).negate().add(sigma)
    val v = e.multiply(sigmaHat).negate().add(r)

    return Proof(comm, sigma, z1, z2, w1, w2, v)
}

fun Proof.verify(public: Public, hash: Hash): Boolean {
    val e = try {
        challenge(hash, public, Comm)
    } catch (e: Exception) {
        return false
    }

    val N0 = public.N
    val NhatArith = public.Aux.n
    val Nhat = NhatArith

    if (!public.Aux.verify(Z1, W1, e, Comm.A, Comm.P)) {
        return false
    }

    if (!public.Aux.verify(Z2, W2, e, Comm.B, Comm.Q)) {
        return false
    }

    val R = public.Aux.s.modPow(N0, NhatArith).multiply(public.Aux.t.modPow(Sigma, NhatArith)).mod(Nhat)

    val lhs = Comm.Q.modPow( Z1, NhatArith).multiply(public.Aux.t.modPow(V, NhatArith)).mod(Nhat)
    val rhs = R.modPow( e, NhatArith).multiply(Comm.T).mod(Nhat)

    if (lhs != rhs) {
        return false
    }

    // DEVIATION: for the bounds to work, we add an extra bit, to ensure that we don't have spurious failures.
    return isInIntervalLEpsPlus1RootN(Z1) && isInIntervalLEpsPlus1RootN(Z2)
}


@Throws(Exception::class)
fun challenge(hash: Hash, public: Public, commitment: Commitment): BigInteger {
    hash.writeAny(public.N, public.Aux, commitment.P, commitment.Q, commitment.A, commitment.B, commitment.T)
    // Figure 28, point 2:
    // Return +-2^eps as the challenge
    return intervalL(hash.digest().inputStream())
    // return sampleIntervalEps(hash.digest())
}