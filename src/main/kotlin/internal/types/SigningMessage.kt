package perun_network.ecdsa_threshold.internal.types

import perun_network.ecdsa_threshold.hash.WriterToWithDomain
import java.io.OutputStream

class SigningMessage(private val message: ByteArray) :WriterToWithDomain {

    // WriteTo writes the message to the given OutputStream.
    override fun writeTo(outputStream: OutputStream): Long {
        outputStream.write(message)
        return message.size.toLong()
    }

    // Domain returns a string representing the domain of the SigningMessage.
    override fun domain(): String {
        return if (message.isEmpty()) {
            "Empty Message"
        } else {
            "Signature Message"
        }
    }
}