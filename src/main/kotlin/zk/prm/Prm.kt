package perun_network.ecdsa_threshold.zk.prm

import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.math.isValidBigModN
import perun_network.ecdsa_threshold.math.sample.SecureRandomInputStream
import perun_network.ecdsa_threshold.math.sample.modN
import perun_network.ecdsa_threshold.params.StatParam
import perun_network.ecdsa_threshold.pool.Pool
import perun_network.ecdsa_threshold.protocols.cmp.pedersen.Parameters
import perun_network.ecdsa_threshold.protocols.cmp.pedersen.Parameters.Companion.validateParameters
import java.math.BigInteger
import java.security.SecureRandom
import kotlin.jvm.Throws

data class Public(val aux: Parameters)

data class Private(
    val lambda: BigInteger,
    val phi: BigInteger,
    val p: BigInteger,
    val q: BigInteger
)

data class Proof(
    val asList: List<BigInteger>,
    val zsList: List<BigInteger>
) {
    fun isValid(public: Public): Boolean {
        if (this == null) return false

        return isValidBigModN(public.aux.n(), *(asList + zsList).toTypedArray())
    }
}

fun newProof(private: Private, hash: Hash, public: Public, pl: Pool): Proof {
    val lambda = private.lambda
    val phi = private.phi

    val n = private.p.multiply(private.q)

    val asList = mutableListOf<BigInteger>()
    val AsList = mutableListOf<BigInteger>()

    val secureRandom = SecureRandomInputStream(SecureRandom.getInstanceStrong())
    pl.parallelize(StatParam) { i ->
        // aᵢ ∈ mod ϕ(N)
        val a = modN(secureRandom, phi)
        asList.add(a)

        // Aᵢ = tᵃ mod N
        val A = public.aux.t().modPow(a, n)
        AsList.add(A)
    }

    val es = challenge(hash, public, AsList)
    // Modular addition is not expensive enough to warrant parallelizing
    val ZsList = mutableListOf<BigInteger>()
    for (i in 0 until StatParam) {
        val z = asList[i]
        // The challenge is public, so branching is ok
        val newZ = if (es[i]) z.add(lambda) else z
        ZsList.add(newZ)
    }

    return Proof(
        asList = AsList,
        zsList = ZsList
    )
}

fun Proof.verify(public: Public, hash: Hash, pl: Pool): Boolean {
    if (validateParameters(public.aux.n(), public.aux.s(), public.aux.t()) != null) return false

    val n = public.aux.n()
    val s = public.aux.s()
    val t = public.aux.t()

    val es = challenge(hash, public, asList)
    val one = BigInteger.ONE

    val verifications = pl.parallelize(StatParam) { i ->
        val z = zsList[i]
        val a = asList[i]

        if (!isValidBigModN(n, a, z)) return@parallelize false

        if (a == one) return@parallelize false

        val lhs = t.modPow(z, n)
        val rhs = if (es[i]) a.multiply(s).mod(n) else a

        lhs == rhs
    }
    return verifications.all { it as Boolean }
}

@Throws(Exception::class)
fun challenge(hash: Hash, public: Public, A: List<BigInteger>): List<Boolean> {
    hash.writeAny(public.aux)
    A.forEach { a -> hash.writeAny(a) }

    val tmpBytes = ByteArray(StatParam)
    hash.digest().copyInto(tmpBytes)

    return tmpBytes.map { it.toInt() and 1 == 1 }
}