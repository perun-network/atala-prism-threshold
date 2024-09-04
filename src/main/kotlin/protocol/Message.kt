package perun_network.ecdsa_threshold.protocol

import perun_network.ecdsa_threshold.party.ID
import perun_network.ecdsa_threshold.hash.Hash
import kotlinx.serialization.Serializable
import perun_network.ecdsa_threshold.hash.BytesWithDomain
import perun_network.ecdsa_threshold.hash.WriterToWithDomain
import perun_network.ecdsa_threshold.internal.round.Number
import kotlin.math.round

@Serializable
data class Message(
    val ssid: ByteArray,
    val from:  ID,
    val to: ID?,
    val protocol: String?,
    val roundNumber: Number?,
    val data: ByteArray?,
    val broadcast: Boolean?,
    val broadcastVerification: ByteArray?,
) {
    override fun toString(): String {
        return "Message: round $roundNumber, from: $data, to: $broadcast, protocol: $protocol"
    }

    fun isFor(id: ID): Boolean {
        if (from == id) return false
        return (to?.equals("")?: false)  || to == id
    }

    fun hash(): ByteArray {
        val content = mutableListOf<WriterToWithDomain>()

        // Add only non-null values to the content list
        content.add(BytesWithDomain("SSID", ssid))
        content.add(from)

        to?.let { content.add(it) }

        protocol?.let {
            content.add(BytesWithDomain("Protocol", protocol.toByteArray()))
        }

        roundNumber?.let {
            content.add(roundNumber)
        }

        data?.let { content.add(BytesWithDomain("Data", it)) }

        val broadcastFlag = if (broadcast == true) 1 else 0
        content.add(BytesWithDomain("Broadcast", ByteArray(1) { broadcastFlag.toByte() }))

        broadcastVerification?.let {
            content.add(BytesWithDomain("BroadcastVerification", it))
        }

        return Hash(content, null).sum()
    }
}

