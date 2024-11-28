package math

import org.junit.jupiter.api.Assertions.assertEquals
import perun_network.ecdsa_threshold.math.SecureRandomInputStream
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class SecureRandomInputStreamTest {

    @Test
    fun `test read single byte`() {
        val secureRandom = SecureRandom()
        val secureStream = SecureRandomInputStream(secureRandom)

        val byteValue = secureStream.read()
        assertTrue(byteValue in 0..255, "The byte should be between 0 and 255")
    }

    @Test
    fun `test read byte array full length`() {
        val secureRandom = SecureRandom()
        val secureStream = SecureRandomInputStream(secureRandom)
        val buffer = ByteArray(10)

        val bytesRead = secureStream.read(buffer)
        assertEquals(10, bytesRead, "Expected to read 10 bytes")
        assertTrue(buffer.all { it in Byte.MIN_VALUE..Byte.MAX_VALUE }, "All bytes should be valid")
    }

    @Test
    fun `test read with offset and length`() {
        val secureRandom = SecureRandom()
        val secureStream = SecureRandomInputStream(secureRandom)
        val buffer = ByteArray(10)

        val bytesRead = secureStream.read(buffer, 2, 5)
        assertEquals(5, bytesRead, "Expected to read 5 bytes into the buffer with offset 2")
        assertTrue(buffer.sliceArray(2 until 7).all { it in Byte.MIN_VALUE..Byte.MAX_VALUE }, "Bytes from offset 2 to 6 should be valid")
    }

    @Test
    fun `test invalid offset throws exception`() {
        val secureRandom = SecureRandom()
        val secureStream = SecureRandomInputStream(secureRandom)
        val buffer = ByteArray(10)

        assertFailsWith<IndexOutOfBoundsException> {
            secureStream.read(buffer, -1, 5)
        }
    }

    @Test
    fun `test invalid length throws exception`() {
        val secureRandom = SecureRandom()
        val secureStream = SecureRandomInputStream(secureRandom)
        val buffer = ByteArray(10)

        assertFailsWith<IndexOutOfBoundsException> {
            secureStream.read(buffer, 0, 11)
        }
    }

    @Test
    fun `test zero length read`() {
        val secureRandom = SecureRandom()
        val secureStream = SecureRandomInputStream(secureRandom)
        val buffer = ByteArray(10)

        assertFailsWith<IndexOutOfBoundsException> {
            secureStream.read(buffer, 0, 0)
        }
    }

    @Test
    fun `test read byte array partially`() {
        val secureRandom = SecureRandom()
        val secureStream = SecureRandomInputStream(secureRandom)
        val buffer = ByteArray(20)

        val bytesRead = secureStream.read(buffer, 5, 10)
        assertEquals(10, bytesRead, "Expected to read 10 bytes into the buffer starting from offset 5")
    }
}