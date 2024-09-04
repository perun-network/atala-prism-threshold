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
import perun_network.ecdsa_threshold.math.curve.Scalar
import perun_network.ecdsa_threshold.party.ID
import perun_network.ecdsa_threshold.protocols.cmp.paillier.CipherText
import perun_network.ecdsa_threshold.protocols.cmp.paillier.PublicKey
import perun_network.ecdsa_threshold.protocols.cmp.presign.AbortNth.Companion.proveNth
import perun_network.ecdsa_threshold.zk.elog.Private
import perun_network.ecdsa_threshold.zk.elog.Proof
import perun_network.ecdsa_threshold.zk.elog.Public
import java.lang.Exception
import java.math.BigInteger

class Presign6(
    private val presign5: Presign5,
    private val helper: Helper,
    private val bigDeltaShares: MutableMap<ID, Point>,
    private val gamma: Point
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
        val body = msg.content as? Broadcast6 ?: return ErrInvalidContent

        if (body.bigDeltaShare.isIdentity()) {
            return ErrNilFields
        }

        val public = Public(
            e = presign5.presign4().presign3().presign2().ElGamalK[msg.from]!!,
            elGamalPublic = presign5.presign4().presign3().presign2().presign1().elGamal[msg.from]!!,
            base = gamma,
            y = body.bigDeltaShare
        )

        if (!body.proof.verify(helper.hashForID(msg.from), public)) {
            return Exception("Failed to validate log* proof for BigDeltaShare")
        }

        bigDeltaShares[msg.from] = body.bigDeltaShare
        return null
    }

    override suspend fun verifyMessage(msg: Message): Exception? {
        return null
    }

    override fun storeMessage(msg: Message): Exception? {
        return null
    }

    override suspend fun finalize(out: Channel<Message>): Pair<Session?, Exception?> {
        // δ = ∑ⱼ δⱼ
        var delta = helper.group().newScalar()
        for (deltaJ in presign5.presign4().deltaShares.values) {
            delta = delta.add(deltaJ)
        }

        // δ⁻¹
        val deltaInv = helper.group().newScalar().set(delta).invert()

        // R = [δ⁻¹] Γ
        val r = deltaInv.act(gamma)

        // δ⋅G
        val bigDeltaExpected = delta.actOnBase()

        // ∑ⱼΔⱼ
        var bigDeltaActual = helper.group().newPoint()
        for (bigDeltaJ in bigDeltaShares.values) {
            bigDeltaActual = bigDeltaActual.add(bigDeltaJ)
        }

        // δ⋅G ?= ∑ⱼΔⱼ
        if (!bigDeltaActual.equals(bigDeltaExpected)) {
            val deltaProofs = mutableMapOf<ID, AbortNth>()
            for (j in otherPartyIDs()) {
                val deltaCiphertext = presign5.presign4().presign3().deltaCiphertext[j]!![selfID()]!! // Dᵢⱼ
                deltaProofs[j] = proveNth(helper.hashForID(selfID()), presign5.presign4().presign3().presign2().presign1().secretPaillier!!, deltaCiphertext)
            }
            val msg = BroadcastAbort1(
                gammaShare = presign5.presign4().presign3().presign2().GammaShare,
                kProof = proveNth(helper.hashForID(selfID()),
                    presign5.presign4().presign3().presign2().presign1().secretPaillier!!,
                    presign5.presign4().presign3().presign2().K[selfID()]!!),
                deltaProofs = deltaProofs
            )
            if (helper.broadcastMessage(out, msg).isFailure) {
                return this to Exception("Broadcast failed in abort phase")
            }
            return Abort1(
                presign6 = this,
                helper = helper,
                gammaShares = mutableMapOf(selfID() to presign5.presign4().presign3().presign2().GammaShare),
                kShares = mutableMapOf(selfID() to presign5.presign4().presign3().presign2().KShare.toBigInteger()),
                deltaAlphas = mutableMapOf(selfID() to presign5.presign4().deltaShareAlpha)
            ) to null
        }

        // Sᵢ = χᵢ⋅R,
        val s = presign5.presign4().chiShare.act(r)

        // {R̄ⱼ = δ⁻¹⋅Δⱼ}ⱼ
        val rBar = mutableMapOf<ID, Point>()
        for ((j, bigDeltaJ) in bigDeltaShares) {
            rBar[j] = deltaInv.act(bigDeltaJ)
        }

        val proof = Proof.newProof(
            helper.group(),
            helper.hashForID(selfID()),
            Public(
                e = presign5.presign4().elGamalChi[selfID()]!!,
                elGamalPublic = presign5.presign4().presign3().presign2().presign1().elGamal[selfID()]!!,
                base = r,
                y = s
            ),
            Private(
                y = presign5.presign4().chiShare,
                lambda = presign5.presign4().elGamalChiNonce
            )
        )

        val broadcastResult = helper.broadcastMessage(out, Broadcast7(
            s = s,
            proof = proof,
            decommitmentID = presign5.presign4().presign3().presign2().DecommitmentID,
            presignatureID = presign5.presign4().presign3().presign2().PresignatureID[selfID()]!!
        ))
        if (broadcastResult.isFailure) {
            return this to broadcastResult.exceptionOrNull() as Exception
        }

        return Presign7(
            presign6 = this,
            helper = helper,
            delta = delta,
            s = mutableMapOf(selfID() to s),
            r = r,
            rBar = rBar
        ) to null
    }

    override fun messageContent(): Content? {
        return null
    }

    override fun broadcastContent(): BroadcastContent {
        return Broadcast6(helper.group().newPoint(), Proof.empty(helper.group()))
    }

    override fun number(): Number {
        return Number(6u)
    }

    fun presign5() = presign5

    fun paillier() : MutableMap<ID, PublicKey> = presign5.presign4().presign3().presign2().presign1().paillier

    fun deltaCiphertext() :MutableMap<ID, MutableMap<ID, CipherText>> = presign5.presign4().presign3().deltaCiphertext

    fun deltaShares() : MutableMap<ID, Scalar> = presign5.presign4().deltaShares

    fun bigGammaShare() : MutableMap<ID, Point> = presign5.bigGammaShare

    fun k() :  MutableMap<ID, CipherText> = presign5.presign4().presign3().presign2().K

    fun commitmentID() = presign5.presign4().presign3().presign2().CommitmentID

    fun elGamalChi() = presign5.presign4().elGamalChi

    fun elGamal() = presign5.presign4().presign3().presign2().presign1().elGamal

    fun presignatureID() = presign5.presign4().presign3().presign2().PresignatureID

    fun publicKey() = presign5.presign4().presign3().presign2().presign1().publicKey

    fun elGamalChiNonce() = presign5.presign4().elGamalChiNonce

    fun secretElGamal() = presign5.presign4().presign3().presign2().presign1().secretElGamal

    fun chiCiphertext() = presign5.presign4().presign3().chiCiphertext

    fun chiShareAlpha() = presign5.presign4().chiShareAlpha

    fun secretPaillier() = presign5.presign4().presign3().presign2().presign1().secretPaillier

    fun kShare() = presign5.presign4().presign3().presign2().KShare

    fun chiShare() = presign5.presign4().chiShare

    fun message() = presign5.presign4().presign3().presign2().presign1().message

}

data class Broadcast6(
    val bigDeltaShare: Point,
    val proof: Proof
) : NormalBroadcastContent() {
    override fun roundNumber(): Number = Number(6u)
}