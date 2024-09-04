package perun_network.ecdsa_threshold.internal.round

import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.math.curve.Curve
import perun_network.ecdsa_threshold.party.ID

// Session represents the current execution of a round-based protocol.
// It embeds the current round, and provides additional functionality.
interface Session: Round {
    // Group returns the group used for this protocol execution.
    fun group(): Curve

    // Hash returns a cloned hash function with the current hash state.
    suspend fun hash(): Hash

    // ProtocolID is an identifier for this protocol.
    fun protocolID(): String

    // FinalRoundNumber is the number of rounds before the output round.
    fun finalRoundNumber(): Number

    // SSID the unique identifier for this protocol execution.
    fun ssid(): ByteArray

    // SelfID is this party's ID.
    fun selfID(): ID

    // PartyIDs is a sorted list of participating parties in this protocol.
    fun partyIDs(): List<ID>

    // OtherPartyIDs returns a sorted list of parties that does not contain SelfID.
    fun otherPartyIDs(): List<ID>

    // Threshold is the maximum number of parties that are assumed to be corrupted during the execution of this protocol.
    fun threshold(): Int

    // N returns the total number of parties participating in the protocol.
    fun n(): Int
}

data class Info (
    val protocolID: String, 	// ProtocolID is an identifier for this protocol
    val finalRoundNumber: Number,// FinalRoundNumber is the number of rounds before the output round.
    val selfID: ID,// SelfID is this party's ID.
    val partyIDs: List<ID>, // PartyIDs is a sorted slice of participating parties in this protocol.
    val threshold: Int,// Threshold is the maximum number of parties that are assumed to be corrupted during the execution of this protocol.
    val group: Curve// Group returns the group used for this protocol execution.
)