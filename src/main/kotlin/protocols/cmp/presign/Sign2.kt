package perun_network.ecdsa_threshold.protocols.cmp.presign

import kotlinx.coroutines.channels.Channel
import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.internal.round.*
import perun_network.ecdsa_threshold.internal.round.Number
import perun_network.ecdsa_threshold.math.curve.Curve
import perun_network.ecdsa_threshold.math.curve.Scalar
import perun_network.ecdsa_threshold.party.ID

class Sign2(
    private val sign1: Sign1,
    private val helper: Helper,
    val sigmaShares: MutableMap<ID, Scalar> = mutableMapOf(),
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
        val signature = sign1.preSignature!!.signature(sigmaShares)

        return if (signature.verify(sign1.publicKey!!, sign1.message)) {
            helper.resultRound(signature) to null
        } else {
            val culprits = sign1.preSignature.verifySignatureShares(sigmaShares, sign1.message)
            helper.abortRound(Exception("Signature failed to verify"), *culprits.toTypedArray()) to null
        }
    }

    override fun messageContent(): Content? {
        return null
    }

    override fun number(): Number {
        return Number(8u)
    }

}

class BroadcastSign2(
    val sigma: Scalar
) : NormalBroadcastContent() {
    override fun roundNumber(): Number {
        return Number(8u)
    }
}