package perun_network.ecdsa_threshold.internal.round

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.SendChannel
import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.math.curve.Curve
import perun_network.ecdsa_threshold.party.ID

class Output (
    private val helper: Helper,
    val result: Any?
) : Session {
    override fun group(): Curve {
        return helper.group()
    }

    override suspend fun hash(): Hash {
        return helper.hash()
    }

    override fun protocolID(): String {
        return helper.protocolID()
    }

    override fun finalRoundNumber(): Number {
        return helper.finalRoundNumber()
    }

    override fun ssid(): ByteArray {
        return helper.ssid()
    }

    override fun selfID(): ID {
        return helper.selfID()
    }

    override fun partyIDs(): List<ID> {
        return helper.partyIDs()
    }

    override fun otherPartyIDs(): List<ID> {
        return helper.otherPartyIDs()
    }

    override fun threshold(): Int {
        return helper.threshold()
    }

    override fun n(): Int {
        return helper.n()
    }

    override suspend fun verifyMessage(msg: Message): Exception? {
        return null
    }

    override fun storeMessage(msg: Message): Exception? {
        return null
    }

    override suspend fun finalize(out: Channel<Message>): Pair<Session?, Exception?> {
        return Pair(this, null)
    }

    override fun messageContent(): Content? {
        return null
    }

    override fun number(): Number {
        return Number(0.toUShort())
    }

}