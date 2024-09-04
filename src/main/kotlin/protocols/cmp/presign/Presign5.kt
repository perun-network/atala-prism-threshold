package perun_network.ecdsa_threshold.protocols.cmp.presign

import kotlinx.coroutines.channels.Channel
import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.internal.elgamal.Ciphertext
import perun_network.ecdsa_threshold.internal.round.*
import perun_network.ecdsa_threshold.internal.round.Number
import perun_network.ecdsa_threshold.internal.round.RoundErrors.ErrInvalidContent
import perun_network.ecdsa_threshold.internal.round.RoundErrors.ErrNilFields
import perun_network.ecdsa_threshold.math.curve.Curve
import perun_network.ecdsa_threshold.math.curve.Point
import perun_network.ecdsa_threshold.party.ID
import perun_network.ecdsa_threshold.zk.logstar.Private
import perun_network.ecdsa_threshold.zk.logstar.Proof
import perun_network.ecdsa_threshold.zk.logstar.Public

class Presign5(
    private val presign4: Presign4,
    private val helper: Helper,
    val bigGammaShare: MutableMap<ID, Point>
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
        val body = msg.content as? Broadcast5 ?: return ErrInvalidContent

        if (body.bigGammaShare.isIdentity()) {
            return ErrNilFields
        }
        bigGammaShare[msg.from] = body.bigGammaShare
        return null
    }

    override suspend fun verifyMessage(msg: Message): Exception? {
        val from = msg.from
        val to = msg.to
        val body = msg.content as? Message5 ?: return ErrInvalidContent

        val public = Public(
            c = presign4.presign3().presign2().G[from]!!,
            x = bigGammaShare[from] ?: return ErrNilFields,
            g = null,
            prover = presign4.presign3().presign2().presign1().paillier[from]!!,
            aux = presign4.presign3().presign2().presign1().pedersen[to]!!
        )

        return if (!body.proofLog.verify(helper.hashForID(from), public)) {
            Exception("Failed to validate log* proof for BigGammaShare")
        } else null
    }

    override fun storeMessage(msg: Message): Exception? = null

    override suspend fun finalize(out: Channel<Message>): Pair<Session?, Exception?> {
        // Γ = ∑ⱼ Γⱼ
        var gamma: Point = helper.group().newPoint()
        for (gammaJ in bigGammaShare.values) {
            gamma = gamma.add(gammaJ)
        }

        // Δᵢ = kᵢ⋅Γ
        val bigDeltaShare = presign4.chiShare.act(gamma)

        val zkPrivate = perun_network.ecdsa_threshold.zk.elog.Private(
             presign4.presign3().presign2().KShare,
             presign4.elGamalChiNonce
        )

        val selfID = helper.selfID()
        val hash = helper.hashForID(selfID)

        val proofLog = perun_network.ecdsa_threshold.zk.elog.Proof.newProof(
            helper.group(),
            hash,
            perun_network.ecdsa_threshold.zk.elog.Public(
                presign4.presign3().presign2().ElGamalK[selfID]!!,
                presign4.presign3().presign2().presign1().elGamal[selfID]!!,
                gamma,
                bigDeltaShare
            ),
            zkPrivate
        )

        val broadcastResult = helper.broadcastMessage(out, Broadcast6(bigDeltaShare, proofLog))
        if (broadcastResult.isFailure) {
            return this to broadcastResult.exceptionOrNull() as Exception
        }

        return Presign6(
            presign5 = this,
            helper = helper,
            gamma = gamma,
            bigDeltaShares = mutableMapOf(selfID to bigDeltaShare)
        ) to null
    }

    override fun messageContent(): Content? {
        return Message5(Proof.empty(helper.group()))
    }

    override fun broadcastContent(): BroadcastContent {
        return Broadcast5(helper.group().newPoint())
    }

    override fun number(): Number = Number(5u)

    fun presign4(): Presign4 = presign4
}

data class Broadcast5(
    val bigGammaShare: Point
) : NormalBroadcastContent() {
    override fun roundNumber(): Number = Number(5u)
}

data class Message5(
    val proofLog: Proof
) : Content {
    override fun roundNumber(): Number = Number(5u)
}