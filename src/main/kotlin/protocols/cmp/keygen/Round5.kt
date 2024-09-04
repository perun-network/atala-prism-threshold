package perun_network.ecdsa_threshold.protocols.cmp.keygen

import kotlinx.coroutines.channels.Channel
import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.internal.round.*
import perun_network.ecdsa_threshold.internal.round.Number
import perun_network.ecdsa_threshold.internal.round.RoundErrors.ErrInvalidContent
import perun_network.ecdsa_threshold.internal.round.RoundErrors.ErrNilFields
import perun_network.ecdsa_threshold.math.curve.Curve
import perun_network.ecdsa_threshold.party.ID
import perun_network.ecdsa_threshold.protocols.cmp.config.Config
import perun_network.ecdsa_threshold.zk.schnorr.Response
import perun_network.ecdsa_threshold.zk.schnorr.emptyResponse

class Round5 (
    private val previousRound: Round4,
    private val helper: Helper,
    val updatedConfig: Config
) : Session, BroadcastRound {
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

    override suspend fun storeBroadcastMessage(msg: Message): Exception? {
        val from = msg.from
        val body = msg.content as? Broadcast5 ?: return ErrInvalidContent

        if (!body.schnorrResponse.isValid()) {
            return ErrNilFields
        }

        if (!body.schnorrResponse.verify(
                helper.hashForID(from),
                updatedConfig.public[from]!!.ecdsa,
                previousRound.schnorrCommitments()[from]!!,
                null
            )
        ) {
            return Exception("Failed to validate schnorr proof for received share")
        }

        return null
    }

    override fun broadcastContent(): BroadcastContent? {
        return Broadcast5(emptyResponse(group()))
    }

    override suspend fun verifyMessage(msg: Message): Exception? {
        return null
    }

    override fun storeMessage(msg: Message): Exception? {
        return null
    }

    override suspend fun finalize(out: Channel<Message>): Pair<Session?, Exception?> {
        return helper.resultRound(updatedConfig) to null
    }

    override fun messageContent(): Content? {
        return null
    }

    override fun number(): Number {
        return Number(5.toUShort())
    }
}

class Broadcast5(
    val schnorrResponse: Response
) : NormalBroadcastContent() {
    override fun roundNumber(): Number {
        return Number(5.toUShort())
    }
}