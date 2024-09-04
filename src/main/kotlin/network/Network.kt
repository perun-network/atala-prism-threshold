package perun_network.ecdsa_threshold.network

import perun_network.ecdsa_threshold.party.ID
import perun_network.ecdsa_threshold.protocol.Message
import kotlinx.coroutines.channels.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.channels.ReceiveChannel

class Network ( private val parties: MutableList<ID>) {
    private val listenChannels = mutableMapOf<ID, Channel<Message>>()
    private val doneChannel = Channel<UInt>()
    private val closedListenChannel = Channel<Message>(capacity = Channel.UNLIMITED).apply { close() }
    private val mutex = Mutex()

    init {
        init()
    }

    private fun init() {
        val N = parties.size
        for (id in parties) {
            listenChannels[id] = Channel(capacity = N*N)
        }
    }

    fun next(id: ID): ReceiveChannel<Message> = runBlocking {
        mutex.withLock {
            if (listenChannels.isEmpty()) {
                init()
            }
            listenChannels[id] ?: closedListenChannel
        }
    }

    fun send(msg: Message) = runBlocking {
        mutex.withLock {
            for ((id, channel) in listenChannels) {
                if (msg.isFor(id)) {
                    channel.send(msg)
                }
            }
        }
    }

    fun done(id: ID) = runBlocking {
        mutex.withLock {
            listenChannels[id]?.let {
                it.close()
                listenChannels.remove(id)
            }
            if (listenChannels.isEmpty()) {
                doneChannel.close()
            }
        }
        doneChannel
    }

    fun quit(id: ID) = runBlocking {
        mutex.withLock {
            parties.remove(id)
        }
    }
}