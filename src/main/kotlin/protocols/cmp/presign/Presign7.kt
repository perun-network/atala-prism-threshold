package perun_network.ecdsa_threshold.protocols.cmp.presign

import kotlinx.coroutines.channels.Channel
import perun_network.ecdsa_threshold.internal.round.*
import perun_network.ecdsa_threshold.internal.types.RID
import perun_network.ecdsa_threshold.math.curve.*
import perun_network.ecdsa_threshold.party.*
import perun_network.ecdsa_threshold.hash.*
import perun_network.ecdsa_threshold.zk.elog.*
import perun_network.ecdsa_threshold.zk.log.*
import perun_network.ecdsa_threshold.ecdsa.PreSignature
import perun_network.ecdsa_threshold.internal.round.Number
import perun_network.ecdsa_threshold.internal.round.RoundErrors.ErrInvalidContent
import perun_network.ecdsa_threshold.internal.round.RoundErrors.ErrNilFields
import perun_network.ecdsa_threshold.internal.types.RID.Companion.emptyRID
import perun_network.ecdsa_threshold.protocols.cmp.presign.AbortNth.Companion.proveNth
import perun_network.ecdsa_threshold.zk.elog.Proof
import perun_network.ecdsa_threshold.zk.elog.Public
import perun_network.ecdsa_threshold.zk.log.Proof.Companion.newProof
import perun_network.ecdsa_threshold.zk.schnorr.emptyProof

class Presign7(
    private val presign6: Presign6,
    private val helper : Helper,
    var delta: Scalar,
    var s: MutableMap<ID, Point>,
    var r: Point,
    var rBar: MutableMap<ID, Point>
) : Session, BroadcastRound {

    override fun group() = presign6.group()
    override suspend fun hash() = presign6.hash()
    override fun protocolID() = presign6.protocolID()
    override fun finalRoundNumber() = presign6.finalRoundNumber()
    override fun ssid() = presign6.ssid()
    override fun selfID() = presign6.selfID()
    override fun partyIDs() = presign6.partyIDs()
    override fun otherPartyIDs() = presign6.otherPartyIDs()
    override fun threshold() = presign6.threshold()
    override fun n() = presign6.n()

    override suspend fun storeBroadcastMessage(msg: Message): Exception? {
        val body = msg.content as? Broadcast7 ?: return ErrInvalidContent

        if (body.s.isIdentity()) {
            return ErrNilFields
        }

        if (body.decommitmentID!!.validate()) {
            return ErrInvalidContent
        }
        if (body.presignatureID!!.validate()) {
            return ErrInvalidContent
        }

        if (!helper.hashForID(msg.from).decommit(
                presign6.commitmentID()[msg.from]!!,
                body.decommitmentID,
                body.presignatureID
            )) {
            return Exception("Failed to decommit presignature ID")
        }

        if (!body.proof.verify(
                helper.hashForID(msg.from),
                Public(
                    e = presign6.elGamalChi()[msg.from]!!,
                    elGamalPublic = presign6.elGamal()[msg.from]!!,
                    base = r,
                    y = body.s
                )
            )) {
            return Exception("Failed to validate elog proof for S")
        }

        s[msg.from] = body.s
        presign6.presignatureID()[msg.from] = body.presignatureID

        return null
    }

    override suspend fun verifyMessage(msg: Message): Exception? {
        return null
    }

    override fun storeMessage(msg: Message): Exception? {
        return null
    }

    override suspend fun finalize(out: Channel<Message>): Pair<Session?, Exception?> {
        // Compute Σ Sⱼ
        var publicKeyComputed = group().newPoint()
        for ((_, sj) in s) {
            publicKeyComputed = publicKeyComputed.add(sj)
        }

        val presignatureID = emptyRID()
        for ((_, id) in presign6.presignatureID()) {
            presignatureID.xor(id)
        }

        // Σ Sⱼ ?= X
        if (!presign6.publicKey()!!.equals(publicKeyComputed)) {
            val yHat = presign6.elGamalChiNonce().act(presign6.elGamal()[selfID()]!!)
            val yHatProof = newProof(
                group(),
                helper.hashForID(selfID()),
                perun_network.ecdsa_threshold.zk.log.Public(
                    h = presign6.elGamalChiNonce().actOnBase(),
                    x = presign6.elGamal()[selfID()]!!,
                    y = yHat
                ),
                perun_network.ecdsa_threshold.zk.log.Private(
                    a = presign6.secretElGamal()!!,
                    b = presign6.elGamalChiNonce()
                )
            )

            val chiProofs = mutableMapOf<ID, AbortNth>()
            for (j in otherPartyIDs()) {
                val chiCiphertext = presign6.chiCiphertext()[j]!![selfID()] // D̂ᵢⱼ
                chiProofs[j] = proveNth(helper.hashForID(selfID()), presign6.secretPaillier()!!, chiCiphertext!!)
            }

            val msg = BroadcastAbort2(
                yHat = yHat,
                yHatProof = yHatProof,
                kProof = proveNth(helper.hashForID(selfID()), presign6.secretPaillier()!!, presign6.k()[selfID()]!!),
                chiProofs = chiProofs
            )

            val broadcastResult = helper.broadcastMessage(out, msg)
            if (broadcastResult.isFailure) {
                return this to broadcastResult.exceptionOrNull() as Exception
            }

            val chiAlphas = mutableMapOf<ID, Scalar>()
            for ((id, chiAlpha) in presign6.chiShareAlpha()) {
                chiAlphas[id] = group().newScalar().setNat(chiAlpha.mod(group().order()))
            }

            return Abort2(
                presign7 = this,
                helper = helper,
                yHat = mutableMapOf(selfID() to yHat),
                kShares = mutableMapOf(selfID() to presign6.kShare()),
                chiAlphas = mutableMapOf(selfID() to chiAlphas)
            ) to null
        }

        val preSignature = PreSignature(
            id = presignatureID,
            r = r,
            rBar = PointMap(rBar),
            s = PointMap(s),
            kShare = presign6.kShare(),
            chiShare = presign6.chiShare()
        )

        return if (presign6.message().isEmpty()) {
            helper.resultRound(preSignature) to null
        } else {
            val rSign1 = Sign1(
                helper = helper,
                publicKey = presign6.publicKey(),
                message = presign6.message()!!,
                preSignature = preSignature
            )
            rSign1.finalize(out)
        }
    }

    override fun messageContent(): Content? {
        return null
    }

    override fun broadcastContent(): BroadcastContent {
        return Broadcast7(
            s = group().newPoint(),
            proof = Proof.empty(group()),
            decommitmentID = null,
            presignatureID = null
        )
    }

    override fun number(): Number {
        return Number(7u)
    }

    fun elGamalChi() = presign6.elGamalChi()

    fun elGamal() = presign6.elGamal()

    fun paillier() =  presign6.paillier()

    fun k() = presign6.k()

    fun ecdsa() = presign6.presign5().presign4().presign3().presign2().presign1().ecdsa

    fun chiCiphertext() = presign6.chiCiphertext()
}

data class Broadcast7(
    val s: Point,
    val proof: perun_network.ecdsa_threshold.zk.elog.Proof,
    val decommitmentID: Decommitment?,
    val presignatureID: RID?
) : NormalBroadcastContent() {
    override fun roundNumber(): Number = Number(7u)
}