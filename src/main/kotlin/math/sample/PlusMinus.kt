package perun_network.ecdsa_threshold.math.sample

import perun_network.ecdsa_threshold.math.curve.Curve
import perun_network.ecdsa_threshold.params.*
import java.io.InputStream
import java.math.BigInteger

// SampleNeg generates a random integer with the given number of bits, potentially negated
fun sampleNeg(rand: InputStream, bits: Int): BigInteger {
    val buf = ByteArray(bits / 8 + 1)
    mustReadBits(rand, buf)
    val neg = buf[0].toInt() and 1
    val out = BigInteger(1, buf.copyOfRange(1, buf.size))
    return if (neg == 1) -out else out
}

// IntervalL returns an integer in the range ± 2^l
fun intervalL(rand: InputStream): BigInteger = sampleNeg(rand, L)

// IntervalLPrime returns an integer in the range ± 2^l'
fun intervalLPrime(rand: InputStream): BigInteger = sampleNeg(rand, LPrime)

// IntervalEps returns an integer in the range ± 2^ε
fun intervalEps(rand: InputStream): BigInteger = sampleNeg(rand, Epsilon)

// IntervalLEps returns an integer in the range ± 2^(l+ε)
fun intervalLEps(rand: InputStream): BigInteger = sampleNeg(rand, LPlusEpsilon)

// IntervalLPrimeEps returns an integer in the range ± 2^(l'+ε)
fun intervalLPrimeEps(rand: InputStream): BigInteger = sampleNeg(rand, LPrimePlusEpsilon)

// IntervalLN returns an integer in the range ± 2^l•N, where N is the size of a Paillier modulus
fun intervalLN(rand: InputStream): BigInteger = sampleNeg(rand, L + BitsIntModN)

// IntervalLN2 returns an integer in the range ± 2^l•N^2
fun intervalLN2(rand: InputStream): BigInteger = sampleNeg(rand, L + 2 * BitsIntModN)

// IntervalLEpsN returns an integer in the range ± 2^(l+ε)•N
fun intervalLEpsN(rand: InputStream): BigInteger = sampleNeg(rand, LPlusEpsilon + BitsIntModN)

// IntervalLEpsN2 returns an integer in the range ± 2^(l+ε)•N^2
fun intervalLEpsN2(rand: InputStream): BigInteger = sampleNeg(rand, LPlusEpsilon + 2 * BitsIntModN)

// IntervalLEpsRootN returns an integer in the range ± 2^(l+ε)•√N
fun intervalLEpsRootN(rand: InputStream): BigInteger = sampleNeg(rand, LPlusEpsilon + BitsIntModN / 2)

// IntervalScalar returns an integer in the range ±q, where q is the size of a Scalar
fun intervalScalar(rand: InputStream, group: Curve): BigInteger = sampleNeg(rand, group.scalarBits())
