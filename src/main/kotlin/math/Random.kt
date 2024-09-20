package perun_network.ecdsa_threshold.math

import perun_network.ecdsa_threshold.ecdsa.Scalar
import java.io.InputStream
import java.math.BigInteger
import java.security.SecureRandom

const val MAX_ITERATIONS = 255

val random = SecureRandomInputStream(SecureRandom.getInstanceStrong())

val ERR_MAX_ITERATIONS = IllegalStateException("sample: failed to generate after $MAX_ITERATIONS iterations")

fun mustReadBits(inputStream: InputStream , buffer: ByteArray) {
    repeat(MAX_ITERATIONS) {
        try {
            inputStream.read(buffer)
            return
        } catch (_: Exception) {
        }
    }
    throw ERR_MAX_ITERATIONS
}

fun sampleUnitModN(n: BigInteger): BigInteger {
    val bitLength = n.bitLength()
    val buf = ByteArray((bitLength + 7) / 8)
    repeat(MAX_ITERATIONS) {
        random.read(buf)
        val candidate = BigInteger(1, buf)
        if (candidate.gcd(n) == BigInteger.ONE) return candidate
    }
    throw ERR_MAX_ITERATIONS
}

// modN samples an element of ℤₙ.
fun modN(n: BigInteger): BigInteger {
    val bitLength = n.bitLength()
    val buf = ByteArray((bitLength + 7) / 8)
    repeat(MAX_ITERATIONS) {
        random.read(buf)
        val candidate = BigInteger(1, buf)
        if (candidate < n) return candidate
    }
    throw ERR_MAX_ITERATIONS
}

// pedersen generates the s, t, λ such that s = tˡ.
fun pedersen(phi: BigInteger, n : BigInteger) : Triple<BigInteger, BigInteger, BigInteger> {
    val lambda = modN(phi)
    val tau  = sampleUnitModN(n)

    // t = τ² mod N
    val t = tau.mod(n).multiply(tau.mod(n)).mod(n)

    // s = tˡ mod N
    val s = t.modPow(lambda, n)
    return Triple(s, t, lambda)
}

// Scalar returns a new *curve.Scalar by reading bytes from rand.
fun sampleScalar(): Scalar {
    val buffer = ByteArray(32)
    random.read(buffer)
    return Scalar(BigInteger(1, buffer))
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