package perun_network.ecdsa_threshold.math

import java.io.InputStream
import java.math.BigInteger

const val SecParam = 256
const val L = 1 * SecParam     // = 256
const val LPrime = 5 * SecParam     // = 1280
const val Epsilon = 2 * SecParam     // = 512
const val LPlusEpsilon = L + Epsilon      // = 768
const val LPrimePlusEpsilon = LPrime + Epsilon // 1792

const val BitsIntModN = 8 * SecParam    // = 2048

const val BitsBlumPrime = 4 * SecParam      // = 1024
const val BitsPaillier = 2 * BitsBlumPrime // = 2048

// sampleNeg generates a random integer with the given number of bits, potentially negated
fun sampleNeg(inputStream: InputStream, bits: Int): BigInteger {
    val buf = ByteArray(bits / 8 + 1)
    mustReadBits(inputStream, buf)
    val neg = buf[0].toInt() and 1
    val out = BigInteger(1, buf.copyOfRange(1, buf.size))
    return if (neg == 1) -out else out
}

fun sampleL() : BigInteger = sampleNeg(random, L)

// IntervalLPrime returns an integer in the range ± 2^l'
fun sampleLPrime(): BigInteger = sampleNeg(random,LPrime)

// sampleLEps returns an integer in the range ± 2^(l+ε)
fun sampleLEps(): BigInteger = sampleNeg(random, LPlusEpsilon)

// sampleLPrimeEps returns an integer in the range ± 2^(l'+ε)
fun sampleLPrimeEps(): BigInteger = sampleNeg(random, LPrimePlusEpsilon)

// sampleLN returns an integer in the range ± 2^l•N, where N is the size of a Paillier modulus
fun sampleLN(): BigInteger = sampleNeg(random, L + BitsIntModN)

// sampleLEpsN returns an integer in the range ± 2^(l+ε)•N
fun sampleLEpsN(): BigInteger = sampleNeg(random, LPlusEpsilon + BitsIntModN)

