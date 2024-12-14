package math

import org.junit.jupiter.api.Assertions.*
import perun_network.ecdsa_threshold.math.isValidModN
import perun_network.ecdsa_threshold.math.jacobi
import perun_network.ecdsa_threshold.math.mustReadBits
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.math.BigInteger
import kotlin.test.Test

class MathTest {
    @Test
    fun `test successful read`() {
        val data = ByteArray(32) { it.toByte() }
        val inputStream = ByteArrayInputStream(data)
        val buffer = ByteArray(32)

        mustReadBits(inputStream, buffer)
        assertArrayEquals(data, buffer, "The buffer should match the input data")
    }

    @Test
    fun `test failure after max iterations`() {
        val failingStream = object : InputStream() {
            override fun read(): Int = throw IOException("Simulated failure")
        }

        val buffer = ByteArray(32)
        assertThrows(IllegalStateException::class.java) {
            mustReadBits(failingStream, buffer)
        }
    }

    @Test
    fun `test jacobi symbol positive cases`() {
        val result1 = jacobi(BigInteger.valueOf(2), BigInteger.valueOf(15))
        assertEquals(1, result1, "Jacobi(2/15) should be 1")

        val result2 = jacobi(BigInteger.valueOf(4), BigInteger.valueOf(7))
        assertEquals(1, result2, "Jacobi(4/7) should be 1")
    }

    @Test
    fun `test jacobi symbol negative cases`() {
        val result = jacobi(BigInteger.valueOf(3), BigInteger.valueOf(5))
        assertEquals(-1, result, "Jacobi(3/15) should be -1")
    }

    @Test
    fun `test jacobi symbol zero cases`() {
        val result = jacobi(BigInteger.ZERO, BigInteger.valueOf(15))
        assertEquals(0, result, "Jacobi(0/15) should be 0")
    }

    @Test
    fun `test jacobi invalid inputs`() {
        assertThrows(IllegalArgumentException::class.java) {
            jacobi(BigInteger.valueOf(5), BigInteger.valueOf(4)) // y is even
        }
    }

    @Test
    fun `test valid integers that are co-prime to N`() {
        val N = BigInteger("10")
        val validInts = arrayOf(BigInteger("1"), BigInteger("3"), BigInteger("7"), BigInteger("9"))
        assertTrue(isValidModN(N, *validInts))
    }

    @Test
    fun `test integers outside valid range`() {
        val N = BigInteger("10")
        val invalidInts = arrayOf(BigInteger("0"), BigInteger("10"), BigInteger("11"))
        assertFalse(isValidModN(N, *invalidInts))
    }

    @Test
    fun `test integers not co-prime to N`() {
        val N = BigInteger("10")
        val nonCoprimeInts = arrayOf(BigInteger("2"), BigInteger("5"), BigInteger("8"))
        assertFalse(isValidModN(N, *nonCoprimeInts))
    }

    @Test
    fun `test null integer`() {
        val N = BigInteger("10")
        val intsWithNull = arrayOf(BigInteger("1"), null, BigInteger("7"))
        assertFalse(isValidModN(N, *intsWithNull))
    }

    @Test
    fun `test negative integer`() {
        val N = BigInteger("10")
        val negativeInts = arrayOf(BigInteger("-3"), BigInteger("1"))
        assertFalse(isValidModN(N, *negativeInts))
    }

    @Test
    fun `test edge case with N as 1`() {
        val N = BigInteger("1")
        val anyInts = arrayOf(BigInteger("1"), BigInteger("0"))
        assertFalse(isValidModN(N, *anyInts))
    }
}