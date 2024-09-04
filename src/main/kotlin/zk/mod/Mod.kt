package perun_network.ecdsa_threshold.zk.mod

import kotlinx.serialization.internal.throwArrayMissingFieldException
import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.math.isValidBigModN
import perun_network.ecdsa_threshold.math.sample.SecureRandomInputStream
import perun_network.ecdsa_threshold.math.sample.modN
import perun_network.ecdsa_threshold.math.sample.qnr
import perun_network.ecdsa_threshold.params.StatParam
import perun_network.ecdsa_threshold.pool.Pool
import java.math.BigInteger
import java.security.SecureRandom

data class Public(val n: BigInteger)

data class Private(val p: BigInteger, val q: BigInteger, val phi: BigInteger)

data class Response(val a: Boolean, val b: Boolean, val x: BigInteger, val z: BigInteger)

data class Proof(val w: BigInteger, val responses: Array<Response?>)


fun isQRmodPQ(y: BigInteger, pHalf: BigInteger, qHalf: BigInteger, p: BigInteger, q: BigInteger): Boolean {
    val oneBigInteger = BigInteger.ONE
    val test = y.modPow(pHalf, p)
    val pOk = test.equals(oneBigInteger)

    val test2 = y.modPow(qHalf, q)
    val qOk = test2.equals(oneBigInteger)

    return pOk && qOk
}

fun fourthRootExponent(phi: BigInteger): BigInteger {
    var e = BigInteger.valueOf(4)
    e = e.add( phi)
    e = e.shiftRight(3).and(BigInteger.ONE.shiftLeft(-1).subtract(BigInteger.ONE))
    e = e.multiply(e).mod(phi)
    return e
}

fun makeQuadraticResidue(y: BigInteger, w: BigInteger, pHalf: BigInteger, qHalf: BigInteger, n: BigInteger, p: BigInteger, q: BigInteger): Triple<Boolean, Boolean, BigInteger> {
    var out = y.mod(n)

    if (isQRmodPQ(out, pHalf, qHalf, p, q)) {
        return Triple(false, false, out)
    }

    // multiply by -1
    out = out.negate().mod(n)
    var a = true
    var b = false
    if (isQRmodPQ(out, pHalf, qHalf, p, q)) {
        return Triple(a, b, out)
    }

    out = out.multiply(w).mod(n)
    b = true
    if (isQRmodPQ(out, pHalf, qHalf, p, q)) {
        return Triple(a, b, out)
    }

    out = out.negate().mod(n)
    a = false
    return Triple(a, b, out)
}

fun Proof.isValid(public: Public): Boolean {
    val n = public.n
    if (jacobi(n, this.w) != -1) return false

    if (!isValidBigModN(n, this.w)) return false

    this.responses.forEach { r ->
        if (r != null) {
            if (!isValidBigModN(n, r.x, r.z)) return false
        }
    }

    return true
}

fun newProof(hash: Hash, private: Private, public: Public, pool: Pool): Proof {
    val n = public.n
    val p = private.p
    val q = private.q
    val phi = private.phi
    val nModulus = p.multiply(q)
    val pHalf = p.shiftRight(1).and(BigInteger.ONE.shiftLeft(-1).subtract(BigInteger.ONE))
    val qHalf = q.shiftRight( 1).and(BigInteger.ONE.shiftLeft(-1).subtract(BigInteger.ONE))
    val w = qnr(SecureRandomInputStream(SecureRandom()), n)

    val nInverse = n.modInverse(phi)
    val e = fourthRootExponent(phi)

    val ys = challenge(hash, n, w)

    var rs = arrayOfNulls<Response>(StatParam)
    pool.parallelize(StatParam) { i ->
        {
            val y = ys[i]

            val z = nModulus.modPow(y, nInverse)
            val (a, b, yPrime) = makeQuadraticResidue(y, w, pHalf, qHalf, n, p, q)
            val x = nModulus.modPow(yPrime, e)

            rs[i] = Response(a, b, x, z);
        }
    }

    return Proof(w, rs)
}

fun Response.verify(n: BigInteger, w: BigInteger, y: BigInteger): Boolean {
    var lhs  = this.z.modPow(n, n)
    if (lhs.compareTo(y) != 0) return false

    lhs = lhs.multiply(this.x).multiply(this.x).mod(n)
    var rhs = y
    if (this.a) rhs = rhs.negate()
    if (this.b) rhs = rhs.multiply(w)
    rhs = rhs.mod(n)

    return lhs.compareTo(rhs) == 0
}

fun Proof.verify(public: Public, hash: Hash, pl : Pool): Boolean {
    val n = public.n
    val nMod = public.n

    if (!n.testBit(0) || n.isProbablePrime(20)) return false

    if (jacobi(n, this.w) != -1) return false

    if (!isValidBigModN(n, this.w)) return false

    try {
        val ys = challenge(hash, nMod, this.w)

        val verifications = pl.parallelize(StatParam) { i ->
            this.responses[i]!!.verify(n, this.w, ys[i])
        }

        return verifications.all { it as Boolean }
    } catch (_ : Exception) {
        return false
    }
}

fun challenge(hash: Hash, n: BigInteger, w: BigInteger): Array<BigInteger> {
    hash.writeAny(n, w)
    val es = Array(StatParam) {
        modN(hash.digest().inputStream(), n)
    }
    return es
}

fun jacobi(x: BigInteger, y: BigInteger): Int {
    if (y == BigInteger.ZERO || y.mod(BigInteger.TWO) == BigInteger.ZERO) {
        throw IllegalArgumentException("y must be a non-zero odd integer.")
    }

    var a = x
    var b = y
    var j = 1

    // If b is negative, adjust j and make b positive
    if (b < BigInteger.ZERO) {
        if (a < BigInteger.ZERO) {
            j = -j
        }
        b = b.negate()
    }

    while (true) {
        if (b == BigInteger.ONE) {
            return j
        }
        if (a == BigInteger.ZERO) {
            return 0
        }
        a = a.mod(b)
        if (a == BigInteger.ZERO) {
            return 0
        }

        // Handle factors of 2 in 'a'
        val s = a.lowestSetBit
        if (s % 2 != 0) {
            val bmod8 = b.mod(BigInteger("8"))
            if (bmod8 == BigInteger("3") || bmod8 == BigInteger("5")) {
                j = -j
            }
        }
        a = a.shiftRight(s) // a = 2^s * c

        // Swap numerator and denomiBigIntegeror
        if (a.mod(BigInteger("4")) == BigInteger("3") && b.mod(BigInteger("4")) == BigInteger("3")) {
            j = -j
        }

        val temp = a
        a = b
        b = temp
    }
}