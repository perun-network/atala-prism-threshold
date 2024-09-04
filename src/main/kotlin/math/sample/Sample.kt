package perun_network.ecdsa_threshold.math.sample

import perun_network.ecdsa_threshold.math.curve.*
import java.io.IOException
import java.math.BigInteger
import java.security.SecureRandom
import java.io.InputStream


const val MAX_ITERATIONS = 255

val ERR_MAX_ITERATIONS = IllegalStateException("sample: failed to generate after $MAX_ITERATIONS iterations")


fun mustReadBits(rand: InputStream, buffer: ByteArray) {
    repeat(MAX_ITERATIONS) {
        try {
            rand.read(buffer)
            return
        } catch (_: Exception) {
        }
    }
    throw ERR_MAX_ITERATIONS
}

// ModN samples an element of ℤₙ.
fun modN(random: InputStream, n: BigInteger): BigInteger {
    val bitLength = n.bitLength()
    val buf = ByteArray((bitLength + 7) / 8)
    repeat(MAX_ITERATIONS) {
        random.read(buf)
        val candidate = BigInteger(1, buf)
        if (candidate < n) return candidate
    }
    throw ERR_MAX_ITERATIONS
}

// UnitModN returns a u ∈ ℤₙˣ.
fun unitModN(random: InputStream, n: BigInteger): BigInteger {
    val bitLength = n.bitLength()
    val buf = ByteArray((bitLength + 7) / 8)
    repeat(MAX_ITERATIONS) {
        random.read(buf)
        val candidate = BigInteger(1, buf)
        if (candidate.gcd(n) == BigInteger.ONE) return candidate
    }
    throw ERR_MAX_ITERATIONS
}

// QNR samples a random quadratic non-residue in Z_n.
fun qnr(random: InputStream, n: BigInteger): BigInteger {
    val buf = ByteArray((n.bitLength() + 7) / 8)
    repeat(MAX_ITERATIONS) {
        random.read(buf)
        val candidate = BigInteger(1, buf).mod(n)
        if (candidate.modPow(n.subtract(BigInteger.ONE).divide(BigInteger.TWO), n) == n.subtract(BigInteger.ONE)) {
            return candidate
        }
    }
    throw ERR_MAX_ITERATIONS
}

// Scalar returns a new *curve.Scalar by reading bytes from rand.
fun scalar(random: InputStream, group: Curve): Scalar {
    val buffer = ByteArray(group.safeScalarBytes())
    random.read(buffer)
    return group.newScalar().setNat(BigInteger(1, buffer))
}

// ScalarUnit returns a new *curve.Scalar by reading bytes from rand.
fun scalarUnit(random: InputStream, group: Curve): Scalar {
    repeat(MAX_ITERATIONS) {
        val s = scalar(random, group)
        if (!s.isZero()) {
            return s
        }
    }
    throw ERR_MAX_ITERATIONS
}

// ScalarPointPair returns a new *curve.Scalar/*curve.Point tuple (x,X) by reading bytes from rand.
fun scalarPointPair(random: InputStream, group: Curve): Pair<Scalar, Point> {
    val s = scalar(random, group)
    return s to s.actOnBase()
}

// Pedersen generates the s, t, λ such that s = tˡ.
fun Pedersen(random: InputStream, phi: BigInteger, n : BigInteger) : Triple<BigInteger, BigInteger, BigInteger> {
    val lambda = modN(random, phi)
    val tau  = unitModN(random, n)

    // t = τ² mod N
    val t = tau.mod(n).multiply(tau.mod(n)).mod(n)

    // s = tˡ mod N
    val s = t.modPow(lambda, n)
    return Triple(s, t, lambda)
}

class SecureRandomInputStream(private val secureRandom: SecureRandom) : InputStream() {

    override fun read(): Int {
        val buffer = ByteArray(1)
        val bytesRead = read(buffer, 0, 1)
        return if (bytesRead == -1) -1 else buffer[0].toInt() and 0xFF
    }

    override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
        if (length <= 0) return 0
        secureRandom.nextBytes(buffer.copyOfRange(offset, offset + length))
        return length
    }
}