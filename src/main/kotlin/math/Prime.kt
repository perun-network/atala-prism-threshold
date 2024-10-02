package perun_network.ecdsa_threshold.math

import java.math.BigInteger
import java.security.SecureRandom

// Function to check if a number is prime
fun isPrime(n: BigInteger): Boolean {
    return n.isProbablePrime(100)
}

// Function to generate a safe Blum prime
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



    // generatePaillierBlumPrimes generates the necessary integers for a Paillier key pair.
    // p, q are safe primes ((p - 1) / 2 is also prime), and Blum primes (p = 3 mod 4)
    // n = pq.
    fun generatePaillierBlumPrimes(): Pair<BigInteger, BigInteger> {
        val p = generateSafeBlumPrime(BitsBlumPrime)
        val q = generateSafeBlumPrime(BitsBlumPrime)

        return Pair(p, q)
    }