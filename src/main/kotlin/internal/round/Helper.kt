package perun_network.ecdsa_threshold.internal.round

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import perun_network.ecdsa_threshold.hash.BytesWithDomain
import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.hash.Hash.Companion.newHash
import perun_network.ecdsa_threshold.hash.WriterToWithDomain
import perun_network.ecdsa_threshold.internal.round.RoundErrors.ErrOutChanFull
import perun_network.ecdsa_threshold.internal.types.ThresholdWrapper
import perun_network.ecdsa_threshold.math.curve.Curve
import perun_network.ecdsa_threshold.party.ID
import perun_network.ecdsa_threshold.party.IDSlice
import perun_network.ecdsa_threshold.pool.Pool

class Helper (
    private val info: Info,
    val pool: Pool?,
    private val partyIDs: IDSlice,
    private val otherPartyIDs: IDSlice,

    private val ssid: ByteArray,

    private val hash: Hash,
) {
    private val mtx = Mutex()

    companion object {
        fun newSession(info: Info, sessionID:ByteArray?, pool: Pool?, vararg auxInfo: WriterToWithDomain): Helper {
            val partyIDs = IDSlice(info.partyIDs)
            require(partyIDs.isNotEmpty()) { "session: partyIDs invalid" }
            require(partyIDs.contains(info.selfID)) { "session: selfID not included in partyIDs" }
            require(info.threshold in 0..UInt.MAX_VALUE.toInt()) { "session: threshold ${info.threshold} is invalid" }
            require(partyIDs.size - 1 >= info.threshold) { "session: threshold ${info.threshold} is invalid for number of parties ${partyIDs.size}" }

            val h = newHash()

            sessionID?.let {
                h.writeAny(BytesWithDomain("Session ID", it))
            }

            h.writeAny(BytesWithDomain("Protocol ID", info.protocolID.toByteArray()))

            info.group?.let {
                h.writeAny(BytesWithDomain("Group Name", it.name().toByteArray()))
            }

            h.writeAny(partyIDs)
            h.writeAny(ThresholdWrapper(info.threshold.toUInt()))

            for (a in auxInfo) {
                h.writeAny(a)
            }

            return Helper(
                info = info,
                pool = pool,
                partyIDs = partyIDs,
                otherPartyIDs = partyIDs.remove(info.selfID),
                ssid = h.clone().sum(),
                hash = h
            )
        }
    }

    // HashForID returns a clone of the hash.Hash for this session, initialized with the given id.
    suspend fun hashForID(id: ID): Hash {
        return mtx.withLock {
            val cloned = hash.clone()
            if (id.toString().isEmpty()) {
                cloned.writeAny(id)
            }
            cloned
        }
    }

    // UpdateHashState writes additional data to the hash state.
    suspend fun updateHashState(value: WriterToWithDomain) {
        mtx.withLock {
            hash?.writeAny(value)
        }
    }

    // BroadcastMessage constructs a Message from the broadcast Content, and sets the header correctly.
    fun broadcastMessage(out: Channel<Message>, broadcastContent: Content): Result<Unit> {
        val msg = Message(from = info.selfID, to = null, broadcast = true, content = broadcastContent)
        return if (out.trySend(msg).isSuccess) {
            Result.success(Unit)
        } else {
            Result.failure(ErrOutChanFull)
        }
    }

    // SendMessage sends content to some party.
    fun sendMessage(out: Channel<Message>, content: Content, to: ID): Result<Unit> {
        val msg = Message(from = info.selfID, to = to, content = content, broadcast = null)
        return if (out.trySend(msg).isSuccess) {
            Result.success(Unit)
        } else {
            Result.failure(ErrOutChanFull)
        }
    }

    // Hash returns a copy of the hash function of this protocol execution.
    suspend fun hash(): Hash {
        val hashClone = mtx.withLock { hash.clone() }
        return hashClone
    }

    // ResultRound returns a round that contains only the result of the protocol.
    fun resultRound(result: Any): Session {
        return Output(this, result)
    }

    // AbortRound returns a round that contains culprits during a faulty execution.
    fun abortRound(err: Exception?, vararg culprits: ID): Session {
        return Abort(this, culprits.toList(), err)
    }

    // ProtocolID returns the protocol ID.
    fun protocolID(): String = info.protocolID

    // FinalRoundNumber returns the number of rounds before the output round.
    fun finalRoundNumber(): Number = info.finalRoundNumber

    // SSID returns the unique identifier for this protocol execution.
    fun ssid(): ByteArray = ssid

    // SelfID returns this party's ID.
    fun selfID(): ID = info.selfID

    // PartyIDs returns a sorted slice of participating parties in this protocol.
    fun partyIDs(): IDSlice = partyIDs

    // OtherPartyIDs returns a sorted list of parties that does not contain SelfID.
    fun otherPartyIDs(): IDSlice = otherPartyIDs

    // Threshold returns the maximum number of parties assumed to be corrupted.
    fun threshold(): Int = info.threshold

    // N returns the number of participants.
    fun n(): Int = info.partyIDs.size

    // Group returns the curve used for this protocol.
    fun group(): Curve = info.group
}