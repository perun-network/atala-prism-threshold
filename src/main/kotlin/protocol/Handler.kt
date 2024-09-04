package perun_network.ecdsa_threshold.protocol

import kotlinx.coroutines.*
import kotlinx.coroutines.channels.ReceiveChannel
import perun_network.ecdsa_threshold.internal.round.Session

typealias StartFunc = (sessionID: ByteArray) -> Session

interface Handler {
    suspend fun result(): Any?
    fun listen(): ReceiveChannel<Message>
    fun stop()
    fun canAccept(msg: Message?): Boolean
    fun accept(msg: Message)
}

