package perun_network.ecdsa_threshold.internal.types

import perun_network.ecdsa_threshold.hash.WriterToWithDomain
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

class ThresholdWrapper(private val value: UInt) : WriterToWithDomain {
    // WriteTo writes the value to the given OutputStream in big-endian format.
    override fun writeTo(outputStream: OutputStream): Long {
        val buffer = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN)
        buffer.putInt(value.toInt())
        val bytes = buffer.array()
        outputStream.write(bytes)
        return bytes.size.toLong()
    }

    // Domain returns a string representing the domain of the ThresholdWrapper.
    override fun domain(): String {
        return "Threshold"
    }
}