package perun_network.ecdsa_threshold.protocols.cmp.presign

import kotlinx.coroutines.channels.Channel
import perun_network.ecdsa_threshold.ecdsa.PreSignature
import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.internal.round.*
import perun_network.ecdsa_threshold.internal.round.Number
import perun_network.ecdsa_threshold.math.curve.Curve
import perun_network.ecdsa_threshold.math.curve.Point
import perun_network.ecdsa_threshold.math.curve.Scalar
import perun_network.ecdsa_threshold.party.ID

class Sign1(
    private val helper: Helper,
    val publicKey: Point?,
    val message : ByteArray,
    val preSignature: PreSignature?
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
        // σᵢ = kᵢm+rχᵢ (mod q)
        val sigmaShare: Scalar = preSignature!!.signatureShare(message)

        val res = helper.broadcastMessage(out, BroadcastSign2(sigmaShare))
        if (res.isFailure) {
            return this to res.exceptionOrNull() as Exception
        }

        return Sign2(
            sign1 = this,
            helper = helper,
            sigmaShares = mutableMapOf(helper.selfID() to sigmaShare)
        ) to null
    }

    override fun messageContent(): Content? {
        return null
    }

    override fun number(): Number {
        return Number(1u)
    }
}