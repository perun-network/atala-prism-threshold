package perun_network.ecdsa_threshold.protocols.cmp.presign

import kotlinx.coroutines.channels.Channel
import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.internal.elgamal.Ciphertext
import perun_network.ecdsa_threshold.internal.elgamal.Ciphertext.Companion.empty
import perun_network.ecdsa_threshold.internal.elgamal.Nonce
import perun_network.ecdsa_threshold.internal.round.*
import perun_network.ecdsa_threshold.internal.round.Number
import perun_network.ecdsa_threshold.internal.round.RoundErrors.ErrInvalidContent
import perun_network.ecdsa_threshold.internal.round.RoundErrors.ErrNilFields
import perun_network.ecdsa_threshold.math.curve.Curve
import perun_network.ecdsa_threshold.math.curve.Scalar
import perun_network.ecdsa_threshold.party.ID
import perun_network.ecdsa_threshold.zk.logstar.Private
import perun_network.ecdsa_threshold.zk.logstar.Proof
import perun_network.ecdsa_threshold.zk.logstar.Public
import java.math.BigInteger


class Presign4(
    private val presign3: Presign3,
    private val helper: Helper,
    val deltaShareAlpha: MutableMap<ID, BigInteger>,
    val chiShareAlpha: MutableMap<ID, BigInteger>,
    val elGamalChiNonce: Nonce,
    val elGamalChi: MutableMap<ID, Ciphertext>,
    val deltaShares: MutableMap<ID, Scalar>,
    val chiShare: Scalar
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
        val body = msg.content as? Broadcast4 ?: return ErrInvalidContent

        if (body.deltaShare.isZero() || !body.elGamalChi.valid()) {
            return ErrNilFields
        }
        elGamalChi[msg.from] = body.elGamalChi
        deltaShares[msg.from] = body.deltaShare
        return null
    }

    override suspend fun verifyMessage(msg: Message): Exception? = null

    override fun storeMessage(msg: Message): Exception? = null

    override suspend fun finalize(out: Channel<Message>): Pair<Session?, Exception?> {
        val bigGammaShare = helper.group().newScalar().setNat(presign3.presign2().GammaShare.mod(group().order())).actOnBase()

        val zkPrivate = Private(
            x = presign3.presign2().GammaShare,
            rho = presign3.presign2().GNonce
        )

        val broadcastResult = helper.broadcastMessage(out, Broadcast5(bigGammaShare))
        if (broadcastResult.isFailure) {
            return this to broadcastResult.exceptionOrNull() as Exception
        }

        val selfID = helper.selfID()
        val hash = helper.hashForID(selfID)

        val otherIDs = presign3.otherPartyIDs()
        val errors = helper.pool!!.parallelize(otherIDs.size) { i ->
            val j = otherIDs[i]
            val proofLog = Proof.newProof(
                helper.group(),
                hash,
                Public(
                    c = presign3.presign2().G[selfID]!!,
                    x = bigGammaShare,
                    g = null,
                    prover = presign3.presign2().presign1().paillier[selfID]!!,
                    aux = presign3.presign2().presign1().pedersen[j]!!
                ),
                zkPrivate
            )

            helper.sendMessage(out, Message5(proofLog), j)
        }
        for (err in errors) {
            val result = err as Result<UInt>
            if (result.isFailure) {
                return this to result.exceptionOrNull() as Exception
            }
        }

        return Presign5(
            presign4 = this,
            helper = helper,
            bigGammaShare = mutableMapOf(selfID to bigGammaShare)
        ) to null
    }

    override fun messageContent() : Content? = null



    override fun broadcastContent(): BroadcastContent {
        return Broadcast4(
            deltaShare = helper.group().newScalar(),
            elGamalChi = empty(helper.group())
        )
    }

    override fun number(): Number = Number(4u)


    fun presign3():Presign3 = presign3
}

data class Broadcast4(
    val deltaShare: Scalar,
    val elGamalChi: Ciphertext
) : NormalBroadcastContent() {
    override fun roundNumber(): Number = Number(4u)
}