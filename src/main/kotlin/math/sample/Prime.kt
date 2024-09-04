package perun_network.ecdsa_threshold.math.sample

import java.math.BigInteger
import java.security.SecureRandom
import java.util.concurrent.Executors
import java.util.concurrent.Future
import kotlin.math.log
import kotlin.math.sqrt

object Params {
    const val BitsBlumPrime = 1024 // Set this according to your requirements
}

object SafePrimeGenerator {

    // The number of numbers to check after our initial prime guess
    private const val sieveSize = 1 shl 18

    // The upper bound on the prime numbers used for sieving
    private const val primeBound = 1 shl 20

    // The number of iterations to use when checking primality
    private const val blumPrimalityIterations = 20

    // The primes will be initialized only once
    private val thePrimes: List<Int> by lazy { generatePrimes(primeBound) }

    // Pool for reusing sieve buffers
    private val sievePool = ThreadLocal.withInitial { BooleanArray(sieveSize) }

    // Generates an array containing all the odd prime numbers < below
    private fun generatePrimes(below: Int): List<Int> {
        val sieve = BooleanArray(below) { true }
        sieve[0] = false
        sieve[1] = false

        for (p in 2..sqrt(below.toDouble()).toInt()) {
            if (sieve[p]) {
                for (i in p * p until below step p) {
                    sieve[i] = false
                }
            }
        }

        val primes = mutableListOf<Int>()
        for (p in 3 until below) {
            if (sieve[p]) primes.add(p)
        }

        return primes
    }

    // Tries to generate a Blum prime using the specified random source
    private fun tryBlumPrime(rand: SecureRandom): BigInteger? {
        val bytes = ByteArray((Params.BitsBlumPrime + 7) / 8)
        rand.nextBytes(bytes)

        // Ensure p = 3 mod 4 by setting the low bits and top two bits
        bytes[bytes.size - 1] = bytes[bytes.size - 1].toInt().or(3).toByte()
        bytes[0] = bytes[0].toInt().or(0xC0).toByte()

        val base = BigInteger(1, bytes)

        val sieve = sievePool.get()
        sieve.fill(true)

        // Remove candidates that aren't 3 mod 4
        for (i in 1 until sieveSize step 4) {
            sieve[i] = false
            sieve[i + 1] = false
            sieve[i + 2] = false
        }

        for (prime in thePrimes) {
            val primeBigInt = BigInteger.valueOf(prime.toLong())
            val r = base.mod(primeBigInt).toInt()
            var firstMultiple = prime - r

            if (r == 0) firstMultiple = 0

            for (i in firstMultiple until sieveSize step prime) {
                sieve[i] = false
                sieve[i + 1] = false
            }
        }

        val p = BigInteger.ZERO
        val q = BigInteger.ZERO

        for (delta in sieve.indices) {
            if (!sieve[delta]) continue

            p.add(base).add(BigInteger.valueOf(delta.toLong()))

            if (p.bitLength() > Params.BitsBlumPrime) return null

            q.shiftRight(1)

            if (!q.isProbablePrime(blumPrimalityIterations)) continue

            if (!p.isProbablePrime(0)) continue

            return p
        }

        return null
    }

    // Paillier generates the necessary integers for a Paillier key pair.
    // p, q are safe primes ((p - 1) / 2 is also prime), and Blum primes (p = 3 mod 4)
    // n = pq.
    fun generatePaillierKeyPair(rand: SecureRandom): Pair<BigInteger?, BigInteger?> {
        val executor = Executors.newFixedThreadPool(2)
        val futures: List<Future<BigInteger?>> = List(2) {
            executor.submit<BigInteger?> { tryBlumPrime(rand) }
        }

        val p = futures[0].get()
        val q = futures[1].get()

        executor.shutdown()
        return Pair(p, q)
    }
}
