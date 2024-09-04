package perun_network.ecdsa_threshold.internal.round

import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.polymorphic
import perun_network.ecdsa_threshold.party.ID

// Content represents the message, either broadcast or P2P returned by a round during finalization.
interface Content {
    fun roundNumber(): Number
}

// BroadcastContent wraps a Content, but also indicates whether this content requires reliable broadcast.
interface BroadcastContent : Content {
    fun reliable(): Boolean
}

// These structs can be embedded in a broadcast message as a way of
// 1. implementing BroadcastContent
// 2. indicating to the handler whether the content should be reliably broadcast
// When non-unanimous halting is acceptable, we can use the echo broadcast.
open class ReliableBroadcastContent : BroadcastContent {
    override fun reliable() = true

    override fun roundNumber(): Number {
        // Implementation of the round number retrieval.
        // This should be provided based on the context where it's used.
        return Number(0u)
    }
}

open class NormalBroadcastContent : BroadcastContent {
    override fun reliable() = false

    override fun roundNumber(): Number {
        // Implementation of the round number retrieval.
        // This should be provided based on the context where it's used.
        return Number(0u)
    }
}

data class Message(
    val from: ID,
    val to: ID?,
    val broadcast: Boolean?,
    val content: Content
)