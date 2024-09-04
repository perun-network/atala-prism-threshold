package perun_network.ecdsa_threshold.protocols.cmp.presign

import perun_network.ecdsa_threshold.internal.round.Number
import kotlinx.coroutines.channels.Channel
import perun_network.ecdsa_threshold.internal.round.*
import perun_network.ecdsa_threshold.internal.round.RoundErrors.ErrInvalidContent
import perun_network.ecdsa_threshold.math.curve.Point
import perun_network.ecdsa_threshold.math.curve.Scalar
import perun_network.ecdsa_threshold.party.ID
import perun_network.ecdsa_threshold.zk.log.Proof
import perun_network.ecdsa_threshold.zk.log.Public

class Abort2(
    private val presign7: Presign7,
    private val helper: Helper,
    val yHat: MutableMap<ID, Point>,
    val kShares: MutableMap<ID, Scalar>,
    val chiAlphas: MutableMap<ID, MutableMap<ID, Scalar>>
) : Session, BroadcastRound {

    override fun group() = presign7.group()
    override suspend fun hash() = presign7.hash()
    override fun protocolID() = presign7.protocolID()
    override fun finalRoundNumber() = presign7.finalRoundNumber()
    override fun ssid() = presign7.ssid()
    override fun selfID() = presign7.selfID()
    override fun partyIDs() = presign7.partyIDs()
    override fun otherPartyIDs() = presign7.otherPartyIDs()
    override fun threshold() = presign7.threshold()
    override fun n() = presign7.n()

    override suspend fun storeBroadcastMessage(msg: Message): Exception? {
        val body = msg.content as? BroadcastAbort2 ?: return ErrInvalidContent

        val alphas = mutableMapOf<ID, Scalar>()
        for ((id, chiProof) in body.chiProofs) {
            alphas[id] = group().newScalar().setNat(chiProof.plaintext.mod(group().order()))
        }
        chiAlphas[msg.from] = alphas
        yHat[msg.from] = body.yHat
        kShares[msg.from] = group().newScalar().setNat(body.kProof!!.plaintext.mod(group().order()))

        if (!body.yHatProof.verify(helper.hashForID(msg.from), Public(
                h = presign7.elGamalChi()[msg.from]!!.l,
                x = presign7.elGamal()[msg.from]!!,
                y = body.yHat
            )
            )) {
            return Exception("Failed to verify YHat log proof")
        }

        val public = presign7.paillier()[msg.from]!!
        if (!body.kProof.verify(helper.hashForID(msg.from), public, presign7.k()[msg.from]!!)) {
            return Exception("Failed to verify validity of k")
        }

        for ((id, chiProof) in body.chiProofs) {
            if (!chiProof.verify(helper.hashForID(msg.from), public, presign7.chiCiphertext()[msg.from]!![id]!!)) {
                return Exception("Failed to validate Delta MtA Nth proof")
            }
        }
        return null
    }

    override suspend fun verifyMessage(msg: Message): Exception? {
        return null
    }

    override fun storeMessage(msg: Message): Exception? {
        return null
    }

    override suspend fun finalize(out: Channel<Message>): Pair<Session?, Exception?> {
        val culprits = mutableListOf<ID>()

        for (j in otherPartyIDs()) {
            // M = Ŷⱼ + kⱼ⋅Xⱼ
            var m = group().newPoint().add(yHat[j]!!).add(kShares[j]!!.act(presign7.ecdsa()[j]!!))
            for (l in partyIDs()) {
                if (l == j) continue

                m = m.add(chiAlphas[j]!![l]!!.actOnBase()) // α̂ⱼₗ⋅G
                m = m.add(kShares[l]!!.act(presign7.ecdsa()[j]!!)) // kₗ⋅Xⱼ
                m = m.sub(chiAlphas[l]!![j]!!.actOnBase()) // -α̂ₗⱼ⋅G
            }

            if (!m.equals(presign7.elGamalChi()[j]!!.m)) {
                culprits.add(j)
            }
        }

        return helper.abortRound(Exception("abort2: detected culprit"), *culprits.toTypedArray()) to null
    }

    override fun messageContent(): Content? {
        return null
    }

    override fun broadcastContent(): BroadcastContent {
        return BroadcastAbort2(
            yHat = group().newPoint(),
            yHatProof = Proof.empty(group()),
            kProof = null,
            chiProofs = mutableMapOf()
        )
    }

    override fun number(): Number {
        return Number(8u)
    }
}

data class BroadcastAbort2(
    val yHat: Point,
    val yHatProof: Proof,
    val kProof: AbortNth?,
    val chiProofs: MutableMap<ID, AbortNth>
) : NormalBroadcastContent() {
    override fun roundNumber(): Number = Number(8u)
}