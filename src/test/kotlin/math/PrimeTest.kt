package math

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import perun_network.ecdsa_threshold.math.generatePaillierBlumPrimes
import perun_network.ecdsa_threshold.math.generateSafeBlumPrime
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertTrue

class PrimeTest {

    @Test
    fun testGenerateSafeBlumPrime() {
        val bits = 256
        val blumPrime = generateSafeBlumPrime(bits)

        // Verify bit length
        assertEquals(bits, blumPrime.bitLength(), "Generated Blum prime should have the specified bit length")

        // Verify Blum prime condition: p ≡ 3 mod 4
        assertEquals(BigInteger.valueOf(3), blumPrime.mod(BigInteger.valueOf(4)), "Blum prime must satisfy p ≡ 3 mod 4")

        // Verify safe prime condition: (p - 1) / 2 is prime
        val halfPrime = blumPrime.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2))
        assertTrue(halfPrime.isProbablePrime(20), "Blum prime must satisfy the safe prime condition")
    }

    @Test
    fun `test generatePaillierBlumPrimes`() {
        val (p, q) = generatePaillierBlumPrimes()

        // Verify that p and q are Blum primes
        listOf(p, q).forEach { prime ->
            assertNotNull(prime, "Generated prime should not be null")
            assertEquals(BigInteger.valueOf(3), prime.mod(BigInteger.valueOf(4)), "Prime must satisfy p ≡ 3 mod 4")
            val halfPrime = prime.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2))
            assertTrue(halfPrime.isProbablePrime(100), "Prime must satisfy the safe prime condition")
        }

        // Verify that p and q are distinct
        assertTrue(p != q, "Generated Blum primes p and q should be distinct")
    }
}