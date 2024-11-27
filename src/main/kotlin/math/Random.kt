package perun_network.ecdsa_threshold.math

import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.ecdsa.secp256k1Order
import java.io.InputStream
import java.math.BigInteger
import java.security.SecureRandom

// Security parameter definition
const val SecParam = 256
const val L = 1 * SecParam     // = 256
const val LPrime = 5 * SecParam     // = 1280
const val Epsilon = 2 * SecParam     // = 512
const val LPlusEpsilon = L + Epsilon      // = 768
const val LPrimePlusEpsilon = LPrime + Epsilon // 1792

const val BitsIntModN = 8 * SecParam    // = 2048

const val BitsBlumPrime = 4 * SecParam      // = 1024
const val BitsPaillier = 2 * BitsBlumPrime // = 2048


/**
 * Maximum number of iterations for random sampling.
 */
const val MAX_ITERATIONS = 255

/**
 * Secure random input stream for generating random bytes.
 */
val random = SecureRandomInputStream(SecureRandom.getInstanceStrong())

/**
 * Exception thrown when the maximum number of iterations is reached without a successful sample.
 */
val ERR_MAX_ITERATIONS = IllegalStateException("sample: failed to generate after $MAX_ITERATIONS iterations")

/**
 * Reads a specified number of bits from the input stream into the provided buffer.
 *
 * This function will attempt to read the buffer up to [MAX_ITERATIONS] times.
 *
 * @param inputStream The input stream to read from.
 * @param buffer The byte array where the read bytes will be stored.
 * @throws IllegalStateException if the maximum number of iterations is reached without reading the buffer.
 */
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

/**
 * Samples a random element from the group of integers modulo `n` that is co-prime to `n`.
 *
 * This function will attempt to generate a valid candidate up to [MAX_ITERATIONS] times.
 *
 * @param n The modulus for the random sampling.
 * @return A random BigInteger in ℤₙ that is co-prime to `n`.
 * @throws IllegalStateException if the maximum number of iterations is reached without finding a valid candidate.
 */
fun sampleModN(n: BigInteger): BigInteger {
    val bitLength = n.bitLength()
    val buf = ByteArray((bitLength + 7) / 8) // guarantees the correct buffer size in bytes.
    repeat(MAX_ITERATIONS) {
        random.read(buf)
        val candidate = BigInteger(buf)
        if (candidate.gcd(n) == BigInteger.ONE) return candidate
    }
    throw ERR_MAX_ITERATIONS
}

/**
 * Samples a random element from the integers modulo `n`.
 *
 * This function will attempt to generate a valid candidate up to [MAX_ITERATIONS] times.
 *
 * @param n The modulus for the random sampling.
 * @return A random BigInteger in ℤₙ.
 * @throws IllegalStateException if the maximum number of iterations is reached without finding a valid candidate.
 */
private fun modN(n: BigInteger): BigInteger {
    val bitLength = n.bitLength()
    val buf = ByteArray((bitLength + 7) / 8) // guarantees the correct buffer size in bytes.
    repeat(MAX_ITERATIONS) {
        random.read(buf)
        val candidate = BigInteger(buf)
        if (candidate < n) return candidate
    }
    throw ERR_MAX_ITERATIONS
}

/**
 * Generates the parameters for the Pedersen commitment.
 *
 * This function samples values for `s`, `t`, and `λ` such that:
 * - `s = t^λ` where `t = τ² mod N`
 *
 * @param phi The value used in the computation of `s`.
 * @param n The modulus used for sampling.
 * @return A Triple containing the values `(s, t, λ)`.
 */
fun samplePedersen(phi: BigInteger, n : BigInteger) : Triple<BigInteger, BigInteger, BigInteger> {
    val lambda = modN(phi)
    val tau  = sampleModN(n)

    // t = τ² mod N
    val t = tau.mod(n).multiply(tau.mod(n)).mod(n)

    // s = t^λ mod N
    val s = t.modPow(lambda, n)
    return Triple(s, t, lambda)
}

/**
 * Samples a new scalar value from a secure random source.
 *
 * This function generates a random 256-bit value, reduces it modulo the secp256k1 order,
 * and ensures it is not zero.
 *
 * @return A new Scalar object.
 */
fun sampleScalar(): Scalar {
    while (true) {
        val buffer = ByteArray(32)  // 32 bytes = 256 bits
        SecureRandom().nextBytes(buffer)  // Fill the buffer with random bytes

        val bigIntValue = BigInteger(1, buffer)  // Use (1, buffer) to avoid negative values

        // Mod the scalar with the curve order to ensure it's within the range [0, secp256k1Order)
        val scalarValue = bigIntValue.mod(secp256k1Order())

        // Ensure the scalar is not zero
        if (scalarValue != BigInteger.ZERO) {
            return Scalar(scalarValue)
        }
    }
}



/**
 * Generates a random integer with the given number of bits, potentially negated.
 *
 * @param inputStream The input stream to read random bytes from.
 * @param bits The number of bits for the random integer.
 * @return A randomly generated BigInteger, which may be negative.
 */
fun sampleNeg(inputStream: InputStream, bits: Int): BigInteger {
    val buf = ByteArray(bits / 8 + 1)
    mustReadBits(inputStream, buf)
    val neg = buf[0].toInt() and 1
    val out = BigInteger(1, buf.copyOfRange(1, buf.size))
    return if (neg == 1) -out else out
}

/**
 * Samples a random integer L in the range ±2^l.
 *
 * @return A randomly generated BigInteger within the specified range.
 */
fun sampleL() : BigInteger = sampleNeg(random, L)

/**
 * Samples a random integer in the range ±2^l'.
 *
 * @return A randomly generated BigInteger within the specified range.
 */
fun sampleLPrime(): BigInteger = sampleNeg(random,LPrime)

/**
 * Samples a random integer in the range ±2^(l+ε).
 *
 * @return A randomly generated BigInteger within the specified range.
 */
fun sampleLEps(): BigInteger = sampleNeg(random, LPlusEpsilon)

/**
 * Samples a random integer in the range ±2^(l'+ε).
 *
 * @return A randomly generated BigInteger within the specified range.
 */
fun sampleLPrimeEps(): BigInteger = sampleNeg(random, LPrimePlusEpsilon)

/**
 * Samples a random integer in the range ±2^l•N, where N is the size of a Paillier modulus.
 *
 * @return A randomly generated BigInteger within the specified range.
 */
fun sampleLN(): BigInteger = sampleNeg(random, L + BitsIntModN)

/**
 * Samples a random integer in the range ±2^(l+ε)•N.
 *
 * @return A randomly generated BigInteger within the specified range.
 */
fun sampleLEpsN(): BigInteger = sampleNeg(random, LPlusEpsilon + BitsIntModN)


/**
 * A secure random input stream that reads bytes from a SecureRandom source.
 *
 * @param secureRandom The SecureRandom instance used for generating random bytes.
 */
class SecureRandomInputStream(private val secureRandom: SecureRandom) : InputStream() {

    /**
     * Reads a single byte from the input stream.
     *
     * @return The byte read as an integer, or -1 if the end of the stream is reached.
     */
    override fun read(): Int {
        val buffer = ByteArray(1)
        val bytesRead = read(buffer, 0, 1)
        return if (bytesRead == -1) -1 else buffer[0].toInt() and 0xFF
    }

    /**
     * Reads a specified number of bytes into the provided buffer.
     *
     * @param buffer The byte array where the read bytes will be stored.
     * @param offset The offset in the array where the read bytes should be stored.
     * @param length The number of bytes to read.
     * @return The number of bytes read.
     * @throws IndexOutOfBoundsException if the offset or length is invalid.
     */
    override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
        if (length <= 0 || offset < 0 || offset >= buffer.size || length > buffer.size - offset) {
            throw IndexOutOfBoundsException("Invalid offset or length")
        }

        secureRandom.nextBytes(buffer)
        return length
    }

    /**
     * Reads all bytes into the provided buffer.
     *
     * @param buffer The byte array where the read bytes will be stored.
     * @return The number of bytes read.
     */
    override fun read(buffer: ByteArray): Int {
        return read(buffer, 0, buffer.size)
    }
}