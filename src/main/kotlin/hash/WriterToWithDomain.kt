package perun_network.ecdsa_threshold.hash

import java.io.OutputStream
import java.io.IOException

// WriterToWithDomain represents a type writing itself, and knowing its domain.
//
// Providing a domain string lets us distinguish the output of different types
// implementing this same interface.
interface WriterToWithDomain {
    @Throws(IOException::class)
    fun writeTo(outputStream: OutputStream): Long

    // Domain returns a context string, which should be unique for each implementor
    fun domain(): String
}

// BytesWithDomain is a useful wrapper to annotate some chunk of data with a domain.
//
// The intention is to wrap some data using this class, and then call writeTo,
// or use this class as a WriterToWithDomain somewhere else.
data class BytesWithDomain(
    private val theDomain: String,
    private val bytes: ByteArray
) : WriterToWithDomain {

    @Throws(IOException::class)
    override fun writeTo(outputStream: OutputStream): Long {
        if (bytes.isEmpty()) {
            throw IOException("Unexpected end of file")
        }
        outputStream.write(bytes)
        return bytes.size.toLong()
    }

    override fun domain(): String {
        return theDomain
    }
}
