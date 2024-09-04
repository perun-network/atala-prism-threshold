package perun_network.ecdsa_threshold.protocols.cmp.sign

import perun_network.ecdsa_threshold.internal.round.RoundErrors.ErrInvalidContent
import perun_network.ecdsa_threshold.internal.round.RoundErrors.ErrNilFields
import perun_network.ecdsa_threshold.math.curve.Curve
import perun_network.ecdsa_threshold.math.curve.Point
import perun_network.ecdsa_threshold.math.curve.Scalar
import perun_network.ecdsa_threshold.party.ID
import kotlinx.coroutines.channels.Channel
import perun_network.ecdsa_threshold.ecdsa.Signature
import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.internal.round.*
import perun_network.ecdsa_threshold.internal.round.Number
import java.lang.Exception
import java.util.concurrent.ConcurrentHashMap

class Sign5(
    private val round4: Sign4,
    private val helper: Helper,
    val sigmaShares: MutableMap<ID, Scalar>,
    val delta: Scalar,
    val bigDelta: Point,
    val bigR: Point,
    val r: Scalar
) : Session, BroadcastRound {

    override fun group(): Curve {
        return round4.group()
    }

    override suspend fun hash(): Hash {
        return helper.hash()
    }

    override fun protocolID(): String {
        return round4.protocolID()
    }

    override fun ssid(): ByteArray {
        return round4.ssid()
    }

    override fun selfID(): ID {
        return round4.selfID()
    }

    override fun partyIDs(): List<ID> {
        return round4.partyIDs()
    }

    override fun otherPartyIDs(): List<ID> {
        return round4.otherPartyIDs()
    }

    override fun threshold(): Int {
        return round4.threshold()
    }

    override fun n(): Int {
        return round4.n()
    }

    override fun finalRoundNumber(): Number {
        return round4.finalRoundNumber()
    }

    override suspend fun storeBroadcastMessage(msg: perun_network.ecdsa_threshold.internal.round.Message): Exception? {
        val body = msg.content as? Broadcast5 ?: return ErrInvalidContent

        if (body.sigmaShare.isZero()) {
            return ErrNilFields
        }

        sigmaShares[msg.from] = body.sigmaShare
        return null
    }

    override suspend fun verifyMessage(msg: perun_network.ecdsa_threshold.internal.round.Message): Exception? {
        return null
    }

    override fun storeMessage(msg: perun_network.ecdsa_threshold.internal.round.Message): Exception? {
        return null
    }

    override suspend fun finalize(out: Channel<perun_network.ecdsa_threshold.internal.round.Message>): Pair<Session?, Exception?> {
        // compute σ = ∑ⱼ σⱼ
        var sigma = group().newScalar()
        for (j in partyIDs()) {
            sigma = sigma.add(sigmaShares[j]!!)
        }

        val signature = Signature(
            r = bigR,
            s = sigma
        )

        if (!signature.verify(round4.publicKey(), round4.message())) {
            return Pair(this, Exception("failed to validate signature"))
        }

        return Pair(helper.resultRound(signature), null)
    }

    override fun messageContent(): perun_network.ecdsa_threshold.internal.round.Content? {
        return null
    }

    override fun broadcastContent(): perun_network.ecdsa_threshold.internal.round.BroadcastContent? {
        return Broadcast5(
            sigmaShare = group().newScalar()
        )
    }

    override fun number(): Number {
        return Number(5u)
    }
}

data class Broadcast5(
    val sigmaShare: Scalar
) : NormalBroadcastContent() {
    override fun roundNumber(): Number {
        return Number(5u)
    }
}