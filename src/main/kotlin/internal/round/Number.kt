package perun_network.ecdsa_threshold.internal.round

import perun_network.ecdsa_threshold.hash.WriterToWithDomain
import java.io.OutputStream
import java.nio.ByteBuffer

// Number is the index of the current round.
// 0 indicates the output round, 1 is the first round.
data class Number(val value: UShort) : WriterToWithDomain {
    // WriteTo implements the io.WriterTo interface.
    override fun writeTo(output: OutputStream): Long {
        val buffer = ByteBuffer.allocate(2).putShort(value.toShort())
        output.write(buffer.array())
        return 2
    }

    // Domain implements hash.WriterToWithDomain.
    override fun domain(): String {
        return "Round Number"
    }
}