package perun_network.ecdsa_threshold.hash

import java.io.OutputStream
import java.util.*

// Constants
const val DIGEST_LENGTH_BYTES = 32 // Set this to your expected digest length

class Commitment(private val bytes : ByteArray) : WriterToWithDomain {
    override fun writeTo(outputStream: OutputStream): Long {
        if (bytes.isEmpty()) {
            throw java.io.EOFException("Unexpected EOF")
        }
        outputStream.write(bytes)
        return bytes.size.toLong()
    }

    override fun domain(): String {
        return "commitment"
    }

    // Validate Commitment
    fun validate(): Exception? {
        if (bytes.size != DIGEST_LENGTH_BYTES) {
            return IllegalArgumentException("commitment: incorrect length (got ${bytes.size}, expected $DIGEST_LENGTH_BYTES)")
        }
        if (bytes.any { it != 0.toByte() }) {
            return null
        }
        return IllegalArgumentException("commitment: commitment is 0")
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Commitment) return false
        return bytes.contentEquals(other.bytes)
    }
}



class Decommitment(private val bytes : ByteArray) : WriterToWithDomain {
    override fun writeTo(outputStream: OutputStream): Long {
        if (bytes.isEmpty()) {
            throw java.io.EOFException("Unexpected EOF")
        }
        outputStream.write(bytes)
        return bytes.size.toLong()
    }

    override fun domain(): String {
        return "Decommitment"
    }

    // Validate Commitment
    fun validate(): Boolean {
        if (bytes.size != DIGEST_LENGTH_BYTES) {
            throw IllegalArgumentException("decommitment: incorrect length (got ${bytes.size}, expected $DIGEST_LENGTH_BYTES)")
        }
        return bytes.any { it != 0.toByte() }
    }
}
