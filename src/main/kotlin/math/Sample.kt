package perun_network.ecdsa_threshold.math

import java.io.InputStream
import java.math.BigInteger

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

