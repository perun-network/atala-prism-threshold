package perun_network.ecdsa_threshold.protocols.cmp.config

import kotlinx.serialization.Serializable
import perun_network.ecdsa_threshold.hash.WriterToWithDomain
import perun_network.ecdsa_threshold.math.curve.Point
import perun_network.ecdsa_threshold.protocols.cmp.paillier.PublicKey
import perun_network.ecdsa_threshold.protocols.cmp.pedersen.Parameters
import java.io.OutputStream

@Serializable
data class Public (
    val ecdsa: Point,
    val elGamal: Point,
    val paillier: PublicKey?,
    val pedersen: Parameters?
) : WriterToWithDomain {
    override fun writeTo(outputStream: OutputStream): Long {
        var total: Long = 0

        // write ECDSA
        val ecdsaData = ecdsa.marshalBinary()
        outputStream.write(ecdsaData)
        total += ecdsaData.size

        // write ElGamal
        val elGamalData = elGamal.marshalBinary()
        outputStream.write(elGamalData)
        total += elGamalData.size

        total += paillier!!.writeTo(outputStream)
        total += pedersen!!.writeTo(outputStream)

        return total
    }

    override fun domain(): String {
        return "Public Data"
    }

}