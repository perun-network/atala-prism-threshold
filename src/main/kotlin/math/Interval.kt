package perun_network.ecdsa_threshold.math

import java.io.InputStream
import java.math.BigInteger

// SampleNeg generates a random integer with the given number of bits, potentially negated
fun sampleNeg(inputStream: InputStream, bits: Int): BigInteger {
    val buf = ByteArray(bits / 8 + 1)
    mustReadBits(inputStream, buf)
    val neg = buf[0].toInt() and 1
    val out = BigInteger(1, buf.copyOfRange(1, buf.size))
    return if (neg == 1) -out else out
}

// IntervalL returns an integer in the range ± 2^l
fun intervalL(): BigInteger = sampleNeg(random, L)

// IntervalLPrime returns an integer in the range ± 2^l'
fun intervalLPrime(): BigInteger = sampleNeg(random,LPrime)

// IntervalEps returns an integer in the range ± 2^ε
fun intervalEps(): BigInteger = sampleNeg(random, Epsilon)

// IntervalLEps returns an integer in the range ± 2^(l+ε)
fun intervalLEps(): BigInteger = sampleNeg(random, LPlusEpsilon)

// IntervalLPrimeEps returns an integer in the range ± 2^(l'+ε)
fun intervalLPrimeEps(): BigInteger = sampleNeg(random, LPrimePlusEpsilon)

// IntervalLN returns an integer in the range ± 2^l•N, where N is the size of a Paillier modulus
fun intervalLN(): BigInteger = sampleNeg(random, L + BitsIntModN)

// IntervalLN2 returns an integer in the range ± 2^l•N^2
fun intervalLN2(): BigInteger = sampleNeg(random, L + 2 * BitsIntModN)

// IntervalLEpsN returns an integer in the range ± 2^(l+ε)•N
fun intervalLEpsN(): BigInteger = sampleNeg(random, LPlusEpsilon + BitsIntModN)

// IntervalLEpsN2 returns an integer in the range ± 2^(l+ε)•N^2
fun intervalLEpsN2(): BigInteger = sampleNeg(random, LPlusEpsilon + 2 * BitsIntModN)

// IntervalLEpsRootN returns an integer in the range ± 2^(l+ε)•√N
fun intervalLEpsRootN(): BigInteger = sampleNeg(random, LPlusEpsilon + BitsIntModN / 2)

// IntervalScalar returns an integer in the range ±q, where q is the size of a Scalar
fun intervalScalar(inputStream: InputStream): BigInteger = sampleNeg(inputStream,256)