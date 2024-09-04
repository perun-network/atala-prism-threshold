package perun_network.ecdsa_threshold.protocol

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.cbor.*
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import perun_network.ecdsa_threshold.hash.BytesWithDomain
import perun_network.ecdsa_threshold.internal.round.*
import perun_network.ecdsa_threshold.internal.round.Number
import perun_network.ecdsa_threshold.internal.round.Message as RoundMessage
import perun_network.ecdsa_threshold.party.ID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentMap

class MultiHandler private constructor(
    private var currentRound: Session,
    private val rounds: MutableMap<Number, Session>,
    private var error: Throwable?,
    private var result: Any?,
    private val messages: ConcurrentMap<Number, ConcurrentMap<ID, Message?>>,
    private val broadcast: ConcurrentMap<Number, ConcurrentMap<ID, Message?>>,
    private val broadcastHashes: ConcurrentMap<Number, ByteArray>,
    private val out: Channel<Message>,
) : Handler {
    private val mutex = Mutex()

    companion object {
        suspend fun newMultiHandler(create: StartFunc, sessionID: ByteArray): MultiHandler {
            val r = create(sessionID)
            val rounds = mutableMapOf(r.number() to r)
            val handler = MultiHandler(
                currentRound = r,
                rounds = rounds,
                error = null,
                result = null,
                messages = newQueue(r.otherPartyIDs(), r.finalRoundNumber()),
                broadcast = newQueue(r.otherPartyIDs(), r.finalRoundNumber()),
                broadcastHashes = ConcurrentHashMap(),
                out = Channel(2 * r.n())
            )
            handler.finalize()
            return handler
        }

        private fun newQueue(senders: List<ID>, rounds: Number): ConcurrentMap<Number, ConcurrentMap<ID, Message?>> {
            val n = senders.size
            val q = ConcurrentHashMap<Number, ConcurrentHashMap<ID, Message?>>()
            for (i in 2.toUShort()..rounds.value) {
                q[Number(i.toUShort())] = ConcurrentHashMap(n)
                for (id in senders) {
                    q[Number(i.toUShort())]!![id] = null
                }
            }
            // Return the ConcurrentHashMap as ConcurrentMap<Number, ConcurrentMap<ID, Message?>>
            @Suppress("UNCHECKED_CAST") // Suppress the unchecked cast warning
            return q as ConcurrentMap<Number, ConcurrentMap<ID, Message?>>
        }
    }

    override suspend fun result(): Any? {
        mutex.withLock {
            error?.let{ throw it }
            return result?: throw IllegalStateException("protocol: not finished")
        }
    }

    override fun listen(): ReceiveChannel<Message> {
        return out
    }


    private fun abort(err: Throwable?, vararg culprits: ID) {
        if (err != null) {
            this.error = err
            runBlocking {
                out.send(
                    Message(
                        ssid = currentRound.ssid(),
                        from = currentRound.selfID(),
                        to = null,
                        protocol = currentRound.protocolID(),
                        roundNumber = null,
                        broadcast = null,
                        broadcastVerification = null,
                        data = err.message?.toByteArray()
                    )
                )
            }
        }
        out.close()
    }

    override fun stop() {
        if (error == null && result == null) {
            abort(Error("aborted by user"), currentRound.selfID())
        }
    }

    private fun expectsNormalMessage(r: Session): Boolean {
        return r.messageContent() != null
    }

    override fun canAccept(msg: Message?): Boolean {
        val r = currentRound
        if (msg == null) return false
        if (!msg.isFor(r.selfID())) return false
        if (msg.protocol != r.protocolID()) return false
        if (!msg.ssid.contentEquals(r.ssid())) return false
        if (!r.partyIDs().contains(msg.from)) return false
        if (msg.data == null) return false
        if (msg.roundNumber == null  || msg.roundNumber.value > r.finalRoundNumber().value) return false
        if (msg.roundNumber.value < r.number().value && msg.roundNumber.value > 0.toUShort()) return false

        return true
    }

    override fun accept(msg: Message) {
        runBlocking {
        mutex.withLock {
            if (!canAccept(msg) || error != null || result != null || duplicate(msg)) {
                return@withLock
            }

            if (msg.roundNumber == Number(0.toUShort())) {
                abort(Error("aborted by other party with error: \"${msg.data}\""), msg.from)
                return@withLock
            }

            store(msg)
            if (currentRound.number() != msg.roundNumber) {
                return@withLock
            }

            if (msg.broadcast == true) {
                val err = verifyBroadcastMessage(msg)
                if (err != null) {
                    abort(err, msg.from)
                    return@withLock
                }
            } else {
                val err = verifyMessage(msg)
                if (err != null) {
                    abort(err, msg.from)
                    return@withLock
                }
            }

            finalize()
        }
            }
    }

    private fun verifyBroadcastMessage(msg: Message): Throwable? {
        val r = rounds[msg.roundNumber] ?: return null
        val roundMsg = getRoundMessage(msg, r)
        if (roundMsg.isFailure) return roundMsg.exceptionOrNull()
        if (r is BroadcastRound) {
            val err = roundMsg.getOrNull()?.let { r.storeBroadcastMessage(it) }
            if (err != null) {
                return Error("round ${r.number()}: $err")
            }

            if (!expectsNormalMessage(r)) {
                return null
            }

            val p2pMsg = messages[msg.roundNumber]?.get(msg.from)
            if (p2pMsg != null) {
                return verifyMessage(p2pMsg)
            }
            return null
        }
        return Error("Round ${r.number()}: is not broadcast round")
    }

    private fun verifyMessage(msg: Message): Throwable? {
        val r = rounds[msg.roundNumber] ?: return null

        if (r is BroadcastRound) {
            val q = broadcast[msg.roundNumber]
            if (q == null || q[msg.from] == null) {
                return null
            }
        }

        val roundMsgRes = getRoundMessage(msg, r)
        if (roundMsgRes.isFailure) return Exception("Round ${r.number()}: ${roundMsgRes.exceptionOrNull()}")
        val roundMsg = roundMsgRes.getOrNull()?: return Exception("Round ${r.number()}: null round message")
        val err = r.verifyMessage(roundMsg)
        if (err != null) {
            return Exception("round ${r.number()}: $err")
        }

        return r.storeMessage(roundMsg)
    }

    private fun finalize() {
        runBlocking {
        if (!receivedAll()) {
            return@runBlocking
        }
        if (!checkBroadcastHash()) {
            abort(Error("broadcast verification failed"))
            return@runBlocking
        }

        val outRoundMessage = Channel<RoundMessage>(currentRound.n() + 1)
        val (r, err) = currentRound.finalize(outRoundMessage)
        outRoundMessage.close()
        if (err != null || r == null) {
            abort(err, currentRound.selfID())
            return@runBlocking
        }

            for (roundMsg in outRoundMessage) {
                val data = Cbor.encodeToByteArray(roundMsg.content)
                val msg = Message(
                    ssid = r.ssid(),
                    from = r.selfID(),
                    to = roundMsg.to,
                    protocol = r.protocolID(),
                    roundNumber = roundMsg.content.roundNumber(),
                    data = data,
                    broadcast = roundMsg.broadcast,
                    broadcastVerification = broadcastHashes[Number((r.number().value - 1.toUShort()).toUShort())]
                )
                if (msg.broadcast == true) {
                    store(msg)
                }
                out.send(msg)
            }

            val roundNumber = r.number()
            rounds[roundNumber] = r
            currentRound = r

            when (val r = r) {
                is Abort -> {
                    abort(r.err, *r.culprits.toTypedArray())
                    return@runBlocking
                }
                is Output -> {
                    result = r.result
                    abort(null)
                    return@runBlocking
                }
                else -> {
                    // handle remaining messages
                    if (r is BroadcastRound) {
                        broadcast[roundNumber]?.values?.forEach { m ->
                            if (m != null && m.from != r.selfID()) {
                                val err = verifyBroadcastMessage(m)
                                if (err != null) {
                                    abort(err, m.from)
                                    return@runBlocking
                                }
                            }
                        }
                    } else {
                        messages[roundNumber]?.values?.forEach { m ->
                            if (m != null) {
                                val err = verifyMessage(m)
                                if (err != null) {
                                    abort(err, m.from)
                                    return@runBlocking
                                }
                            }
                        }
                    }
                }
            }

            finalize()
        }
    }



    private suspend fun receivedAll(): Boolean {
        val r = currentRound
        val number = r.number()

        if (r is BroadcastRound) {
            val broadcastQueue = broadcast[number] ?: return true
            for (id in r.partyIDs()) {
                if (broadcastQueue[id] == null) {
                    return false
                }
            }

            if (broadcastHashes[number] == null) {
                val hashState = r.hash()
                for (msg in broadcastQueue.values) {
                    msg?.let {
                        hashState.writeAny(BytesWithDomain("Message", it.hash()))
                    }
                }
                broadcastHashes[number] = hashState.sum()
            }
        }

        if (expectsNormalMessage(r)) {
            val messageQueue = messages[number] ?: return true
            for (id in r.otherPartyIDs()) {
                if (messageQueue[id] == null) {
                    return false
                }
            }
        }
        return true
    }

    private fun duplicate(msg: Message): Boolean {
        if (msg.roundNumber == Number(0.toUShort())) return false

        val r = rounds[msg.roundNumber] ?: return false

        if (msg.broadcast == true) {
            val broadcastQueue = broadcast[r.number()] ?: return false
            if (broadcastQueue[msg.from] != null) {
                return true
            }
        } else {
            val messageQueue = messages[r.number()] ?: return false
            if (messageQueue[msg.from] != null) {
                return true
            }
        }
        return false
    }

    private fun store(msg: Message) {
        if (msg.roundNumber == Number(0.toUShort())) return
        val r = rounds[msg.roundNumber] ?: return
        if (msg.broadcast == true) {
            val broadcastQueue = broadcast[r.number()] ?: return
            broadcastQueue[msg.from] = msg
        } else {
            val messageQueue = messages[r.number()] ?: return
            messageQueue[msg.from] = msg
        }
    }

    private fun getRoundMessage(msg: Message, r: Session): Result<RoundMessage> {
        // Determine content type based on whether the message is a broadcast
        var content: Content?
        content = when {
            msg.broadcast == true -> {
                val broadcastRound = r as? BroadcastRound
                    ?: return Result.failure(Error("Got broadcast message when none was expected"))
                broadcastRound.broadcastContent()
            }
            else -> r.messageContent()
        }

        // Ensure msg.data is not null
        val data = msg.data ?: return Result.failure(Error("msg.data is null"))

        // unmarshal message
        return try {
            // Unmarshal message data based on the message type
            content = if (msg.broadcast == true) {
                Cbor.decodeFromByteArray<BroadcastContent>(data) // Replace with the actual type
            } else {
                Cbor.decodeFromByteArray<Content>(data) // Replace with the actual type
            }
            val roundMsg = RoundMessage(
                from = msg.from,
                to = msg.to ?: throw IllegalArgumentException("msg.to is null"),
                content = content,
                broadcast = msg.broadcast?: throw IllegalArgumentException("msg.broadcast is null"),
            )
            Result.success(roundMsg)
        } catch (e: Exception) {
            Result.failure(Error("failed to unmarshal: ${e.message}"))
        }
    }

    private suspend fun checkBroadcastHash(): Boolean {
        val r = currentRound
        if (r is BroadcastRound && broadcastHashes[r.number()] != null) {
            val hashState = r.hash()
            for (msg in broadcast[r.number()]!!.values) {
                msg?.let {
                    hashState.writeAny(BytesWithDomain("Message", it.hash()))
                }
            }
            return hashState.sum().contentEquals(broadcastHashes[r.number()])
        }
        return true
    }
}