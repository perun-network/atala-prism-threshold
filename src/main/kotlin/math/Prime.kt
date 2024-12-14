package perun_network.ecdsa_threshold.math

import java.math.BigInteger
import java.security.SecureRandom

/**
 * Checks if a number is prime using a probabilistic method.
 *
 * @param n The number to check for primality.
 * @return `true` if n is probably prime; `false` otherwise.
 */
private fun isPrime(n: BigInteger): Boolean {
    return n.isProbablePrime(100) // 100 is the certainty level for the primality test
}

/**
 * Generates a safe Blum prime of the specified bit length.
 * A safe Blum prime is a prime number p such that p ≡ 3 (mod 4) and (p - 1) / 2 is also prime.
 *
 * @param bits The bit length of the desired Blum prime.
 * @return A safe Blum prime as a BigInteger.
 */
fun generateSafeBlumPrime(bits: Int): BigInteger {
    val random = SecureRandom()
    var prime: BigInteger
    do {
        // Generate a prime candidate
        prime = BigInteger.probablePrime(bits, random)

        // Ensure p ≡ 3 mod 4 (Blum prime condition)
        if (prime.mod(BigInteger.valueOf(4)) == BigInteger.valueOf(3)) {
            // Check if (p - 1) / 2 is prime (safe prime condition)
            val halfPrime = prime.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2))
            if (isPrime(halfPrime)) {
                break
            }
        }
    } while (true)
    return prime
}

/**
 * Generates the necessary integers for a Paillier key pair.
 * Returns a pair of safe Blum primes (p, q) such that both p and q are:
 * 1. Safe primes (p - 1) / 2 is also prime
 * 2. Blum primes (p = 3 mod 4).
 *
 * @return A pair containing two safe Blum primes as BigIntegers.
 */
fun generatePaillierBlumPrimes(): Pair<BigInteger, BigInteger> {
    val p = generateSafeBlumPrime(BitsBlumPrime)
    val q = generateSafeBlumPrime(BitsBlumPrime)
    return Pair(p, q)
}