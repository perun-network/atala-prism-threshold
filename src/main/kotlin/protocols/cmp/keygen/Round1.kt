package perun_network.ecdsa_threshold.protocols.cmp.keygen

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.SendChannel
import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.internal.round.*
import perun_network.ecdsa_threshold.internal.round.Number
import perun_network.ecdsa_threshold.internal.types.RID
import perun_network.ecdsa_threshold.internal.types.RID.Companion.newRID
import perun_network.ecdsa_threshold.math.curve.Curve
import perun_network.ecdsa_threshold.math.curve.Point
import perun_network.ecdsa_threshold.math.curve.Scalar
import perun_network.ecdsa_threshold.math.polynomial.Exponent.Companion.newPolynomialExponent
import perun_network.ecdsa_threshold.math.polynomial.Polynomial
import perun_network.ecdsa_threshold.math.sample.SecureRandomInputStream
import perun_network.ecdsa_threshold.math.sample.scalarPointPair
import perun_network.ecdsa_threshold.party.ID
import perun_network.ecdsa_threshold.protocols.cmp.paillier.newSecretKey
import perun_network.ecdsa_threshold.zk.schnorr.newRandomness
import java.security.SecureRandom

class Round1 (
    private val helper: Helper,

    // Previous secret ECDSA key share
    val previousSecretECDSA: Scalar? = null,

    // Previous public shares for ECDSA
    var previousPublicSharesECDSA: MutableMap<ID, Point> = mutableMapOf(),

    // Previous chain key
    var previousChainKey: RID? = null,

    // Polynomial for VSS secret
    var vssSecret: Polynomial? = null,
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
        return try {
            // Example of generating cryptographic keys
            val paillierSecret = newSecretKey()
            val selfPaillierPublic = paillierSecret.publicKey
            val (selfPedersenPublic, pedersenSecret) = paillierSecret.generatePedersen()

            val (elGamalSecret, elGamalPublic) = scalarPointPair(SecureRandomInputStream(SecureRandom()), helper.group())

            // Example of evaluating and generating polynomial
            val selfShare = vssSecret?.evaluate(helper.selfID().scalar(helper.group()))
                ?: throw IllegalStateException("VSS secret is null")
            val selfVSSPolynomial = newPolynomialExponent(vssSecret
                ?: throw IllegalStateException("VSS secret is null"))

            // Generate Schnorr randomness
            val schnorrRand = newRandomness(SecureRandom(), helper.group(), null)

            // Sample RID and chain key
            val selfRID = newRID(SecureRandom()) ?: throw IllegalStateException("Failed to sample RID")
            val chainKey = newRID(SecureRandom()) ?: throw IllegalStateException("Failed to sample chain key")

            // Commit to data
            val (selfCommitment, decommitment) = helper.hashForID(helper.selfID()).commit(
                selfRID, chainKey, selfVSSPolynomial, schnorrRand.commitment(), elGamalPublic,
                selfPedersenPublic.n, selfPedersenPublic.s, selfPedersenPublic.t
            )

            // Send message to the channel
            val msg = Broadcast2(selfCommitment)
            helper.broadcastMessage(out, msg)

            // Prepare the next round
            val nextRound = Round2(
                previousRound = this,
                helper = helper,
                vssPolynomials = mutableMapOf(helper.selfID() to selfVSSPolynomial),
                commitments = mutableMapOf(helper.selfID() to selfCommitment),
                rids = mutableMapOf(helper.selfID() to selfRID),
                chainKeys = mutableMapOf(helper.selfID() to chainKey),
                shareReceived = mutableMapOf(helper.selfID() to selfShare),
                elGamalPublic = mutableMapOf(helper.selfID() to elGamalPublic),
                paillierPublic = mutableMapOf(helper.selfID() to selfPaillierPublic),
                pedersen = mutableMapOf(helper.selfID() to selfPedersenPublic),
                elGamalSecret = elGamalSecret,
                paillierSecret = paillierSecret,
                pedersenSecret = pedersenSecret,
                schnorrRand = schnorrRand,
                decommitment = decommitment
            )

            Pair(nextRound, null)
        } catch (e: Exception) {
            Pair(null, e)
        }
    }

    override fun messageContent(): Content? {
        return null
    }

    override fun number(): Number {
        return Number(1.toUShort())
    }

}