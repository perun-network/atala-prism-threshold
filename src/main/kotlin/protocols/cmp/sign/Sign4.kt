package perun_network.ecdsa_threshold.protocols.cmp.sign

import perun_network.ecdsa_threshold.internal.round.RoundErrors.ErrInvalidContent
import perun_network.ecdsa_threshold.internal.round.RoundErrors.ErrNilFields
import perun_network.ecdsa_threshold.math.curve.Curve
import perun_network.ecdsa_threshold.math.curve.Point
import perun_network.ecdsa_threshold.math.curve.Scalar
import perun_network.ecdsa_threshold.party.ID
import perun_network.ecdsa_threshold.zk.logstar.Public as zklogstarPublic
import perun_network.ecdsa_threshold.zk.logstar.Proof as zklogstarProof
import java.lang.Exception
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.channels.Channel
import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.internal.round.*
import perun_network.ecdsa_threshold.internal.round.Number
import perun_network.ecdsa_threshold.math.curve.fromHash

class Sign4(
    private val round3: Sign3,
    private val helper: Helper,
    val deltaShares: MutableMap<ID, Scalar>,
    val bigDeltaShares: MutableMap<ID, Point>,
    var gamma: Point,
    var chiShare: Scalar
) : Session, BroadcastRound {

    override fun group(): Curve {
        return round3.group()
    }

    override suspend fun hash(): Hash {
        return helper.hash()
    }

    override fun protocolID(): String {
        return round3.protocolID()
    }

    override fun ssid(): ByteArray {
        return round3.ssid()
    }

    override fun selfID(): ID {
        return round3.selfID()
    }

    override fun partyIDs(): List<ID> {
        return round3.partyIDs()
    }

    override fun otherPartyIDs(): List<ID> {
        return round3.otherPartyIDs()
    }

    override fun threshold(): Int {
        return round3.threshold()
    }

    override fun n(): Int {
        return round3.n()
    }

    override fun finalRoundNumber(): Number {
        return round3.finalRoundNumber()
    }

    override suspend fun storeBroadcastMessage(msg: Message): Exception? {
        val body = msg.content as? Broadcast4 ?: return ErrInvalidContent

        if (body.deltaShare.isZero() || body.bigDeltaShare.isIdentity()) {
            return ErrNilFields
        }

        bigDeltaShares[msg.from] = body.bigDeltaShare
        deltaShares[msg.from] = body.deltaShare
        return null
    }

    override suspend fun verifyMessage(msg: Message): Exception? {
        val from = msg.from
        val to = msg.to
        val body = msg.content as? Message4 ?: return ErrInvalidContent

        val zkLogPublic = zklogstarPublic(
            c = round3.k()[from]!!,
            x = bigDeltaShares[from]!!,
            g = gamma,
            prover = round3.paillier()[from]!!,
            aux = round3.pedersen()[to]!!
        )

        if (!body.proofLog!!.verify(helper.hashForID(from), zkLogPublic)) {
            return Exception("failed to validate log proof")
        }

        return null
    }

    override fun storeMessage(msg: Message): Exception? {
        return null
    }

    override suspend fun finalize(out: Channel<Message>): Pair<Session?, Exception?> {
        // δ = ∑ⱼ δⱼ
        // Δ = ∑ⱼ Δⱼ
        var delta = group().newScalar()
        var bigDelta = group().newPoint()
        for (j in partyIDs()) {
            delta = delta.add(deltaShares[j]!!)
            bigDelta = bigDelta.add(bigDeltaShares[j]!!)
        }

        // Δ == [δ]G
        val deltaComputed = delta.actOnBase()
        if (!deltaComputed.equals(bigDelta)) {
            return Pair(this, Exception("computed Δ is inconsistent with [δ]G"))
        }

        val deltaInv = delta.invert() // δ⁻¹
        val bigR = deltaInv.act(gamma) // R = [δ⁻¹] Γ
        val r = bigR.xScalar() // r = R|ₓ

        // km = Hash(m)⋅kᵢ
        val km = fromHash(group(), round3.message()).mul(round3.kShare())

        // σᵢ = rχᵢ + kᵢm
        val sigmaShare = group().newScalar().set(r!!).mul(chiShare).add(km)

        // Send to all
        val broadcastRes = helper.broadcastMessage(out, Broadcast5(sigmaShare))
        if (broadcastRes.isFailure) {
            return Pair(this, broadcastRes.exceptionOrNull() as Exception)
        }
        return Pair(Sign5(this, helper, mutableMapOf(selfID() to sigmaShare), delta, bigDelta, bigR, r), null)
    }

    override fun messageContent(): Content {
        return Message4(zklogstarProof.empty(group()))
    }

    override fun broadcastContent(): BroadcastContent? {
        return Broadcast4(
            deltaShare = group().newScalar(),
            bigDeltaShare = group().newPoint()
        )
    }

    override fun number(): Number {
        return Number(4u)
    }

    fun publicKey() = round3.publicKey()

    fun message() = round3.message()
}

data class Message4(
    val proofLog: zklogstarProof? = null
) : Content {
    override fun roundNumber(): Number {
        return Number(4u)
    }
}

data class Broadcast4(
    val deltaShare: Scalar,
    val bigDeltaShare: Point
) : NormalBroadcastContent() {
    override fun roundNumber(): Number {
        return Number(4u)
    }
}