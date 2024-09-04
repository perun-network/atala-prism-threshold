package perun_network.ecdsa_threshold.protocols.cmp.keygen

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.SendChannel
import perun_network.ecdsa_threshold.hash.Commitment
import perun_network.ecdsa_threshold.hash.Decommitment
import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.internal.round.*
import perun_network.ecdsa_threshold.internal.round.Number
import perun_network.ecdsa_threshold.internal.round.RoundErrors.ErrInvalidContent
import perun_network.ecdsa_threshold.internal.types.RID
import perun_network.ecdsa_threshold.math.curve.Curve
import perun_network.ecdsa_threshold.math.curve.Point
import perun_network.ecdsa_threshold.math.curve.Scalar
import perun_network.ecdsa_threshold.math.polynomial.Exponent
import perun_network.ecdsa_threshold.math.polynomial.Polynomial
import perun_network.ecdsa_threshold.party.ID
import perun_network.ecdsa_threshold.protocols.cmp.paillier.PublicKey
import perun_network.ecdsa_threshold.protocols.cmp.paillier.SecretKey
import perun_network.ecdsa_threshold.protocols.cmp.pedersen.Parameters
import perun_network.ecdsa_threshold.zk.schnorr.Randomness
import java.math.BigInteger

class Round2(
    private val previousRound: Round1,
    private val helper: Helper,

    // Maps to store various data as per the original Go code
    val vssPolynomials: MutableMap<ID, Exponent>,
    val commitments: MutableMap<ID, Commitment>,
    val rids: MutableMap<ID, RID>,
    val chainKeys: MutableMap<ID, RID>,
    val shareReceived: MutableMap<ID, Scalar>,
    val elGamalPublic: MutableMap<ID, Point>,
    val paillierPublic: MutableMap<ID, PublicKey>,
    val pedersen: MutableMap<ID, Parameters>,
    val elGamalSecret: Scalar,
    val paillierSecret: SecretKey,
    val pedersenSecret: BigInteger,
    val schnorrRand: Randomness,
    val decommitment: Decommitment,

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

    override suspend fun verifyMessage(msg: Message): Exception? {
        return null
    }

    override fun storeMessage(msg: Message): Exception? {
        return null
    }

    override suspend fun finalize(out: Channel<Message>): Pair<Session?, Exception?> {
        val msg = Broadcast3(
            rid = rids[selfID()],
            chainKey = chainKeys[selfID()],
            vssPolynomial = vssPolynomials[selfID()],
            schnorrCommitments = schnorrRand.commitment(),
            elGamalPublic = elGamalPublic[selfID()],
            n = pedersen[selfID()]?.n(),
            s = pedersen[selfID()]?.s(),
            t = pedersen[selfID()]?.t(),
            decommitment = decommitment
        )

        helper.broadcastMessage(out, msg)

        val nextRound = Round3(
            this,
            this.helper,
            mutableMapOf<ID, perun_network.ecdsa_threshold.zk.schnorr.Commitment>()
        )
        return Pair(nextRound, null)
    }

    override fun messageContent(): Content? {
        return null
    }

    override fun number(): Number {
        return Number(2.toUShort())
    }

    override suspend fun storeBroadcastMessage(msg: Message): Exception? {
        val body = msg.content as? Broadcast2 ?: return ErrInvalidContent
        val exc =  body.commitment!!.validate()
        if (exc != null) {
            return exc
        }

        commitments[msg.from] = body.commitment
        return null
    }

    override fun broadcastContent(): BroadcastContent? {
        return Broadcast2(null)
    }

    fun vssSecret() : Polynomial? {
        return previousRound.vssSecret
    }

    fun previousChainKey() : RID? {
        return previousRound.previousChainKey
    }

    fun previousSecretECDSA() : Scalar? {
        return previousRound.previousSecretECDSA
    }

    fun previousPublicSharesECDSA () : MutableMap<ID, Point> {
        return previousRound.previousPublicSharesECDSA
    }

}

class Broadcast2 (
    val commitment: Commitment?,
) : ReliableBroadcastContent() {
    override fun roundNumber(): Number {
        return Number(2.toUShort())
    }
}