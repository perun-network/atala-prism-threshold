package perun_network.ecdsa_threshold.internal.types

import kotlinx.serialization.Serializable
import perun_network.ecdsa_threshold.hash.WriterToWithDomain
import perun_network.ecdsa_threshold.internal.params.SEC_BYTES
import java.io.InputStream
import java.io.OutputStream
import java.security.SecureRandom
import kotlin.experimental.xor

// RID represents a byte array whose size equals the security parameter.
// It can be easily XOR'ed with other RID. An empty array is considered invalid.
@Serializable
class RID(val bytes: ByteArray) :WriterToWithDomain {

    init {
        require(bytes.size == SEC_BYTES) { "RID must be of size ${SEC_BYTES}" }
    }

    companion object {
        // Create an empty (zeroed-out) RID
        fun emptyRID(): RID {
            return RID(ByteArray(SEC_BYTES))
        }

        fun newRID(secureRandom: SecureRandom): RID {
            val bytesRead = ByteArray(SEC_BYTES)
            secureRandom.nextBytes(bytesRead)
            return RID(bytesRead)
        }
    }

    // XOR modifies the receiver by taking the XOR with the argument.
    fun xor(otherRID: RID) {
        for (i in bytes.indices) {
            bytes[i] = (bytes[i] xor otherRID.bytes[i])
        }
    }

    override fun writeTo(outputStream: OutputStream): Long {
        outputStream.write(bytes)
        return bytes.size.toLong()
    }

    override fun domain(): String {
        return "RID"
    }

    // Validate ensures that the RID is the correct length and is not identically 0.
    fun validate(): Boolean {
        if (bytes.size != SEC_BYTES) {
            return false
        }
        return bytes.any { it != 0.toByte() }
    }

    // Copy returns a copy of the RID.
    fun copy(): RID {
        return RID(bytes.copyOf())
    }

    // Method to retrieve the byte array
    fun toByteArray(): ByteArray {
        return bytes
    }
}