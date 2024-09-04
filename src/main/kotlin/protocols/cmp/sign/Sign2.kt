package perun_network.ecdsa_threshold.protocols.cmp.sign

import kotlinx.coroutines.channels.Channel
import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.internal.mta.proveAffG
import perun_network.ecdsa_threshold.internal.round.*
import perun_network.ecdsa_threshold.internal.round.Number
import perun_network.ecdsa_threshold.internal.round.RoundErrors.ErrInvalidContent
import perun_network.ecdsa_threshold.math.curve.Curve
import perun_network.ecdsa_threshold.math.curve.Point
import perun_network.ecdsa_threshold.math.curve.Scalar
import perun_network.ecdsa_threshold.math.curve.makeInt
import perun_network.ecdsa_threshold.party.ID
import perun_network.ecdsa_threshold.protocols.cmp.paillier.CipherText
import perun_network.ecdsa_threshold.zk.enc.Public
import java.math.BigInteger

class Sign2(
    private val round1: Sign1,
    private val helper: Helper,
    val k: MutableMap<ID, CipherText>,
    val g: MutableMap<ID, CipherText>,
    val bigGammaShare: MutableMap<ID, Point>,
    val gammaShare: BigInteger,
    val kShare: Scalar,
    val kNonce: BigInteger,
    val gNonce: BigInteger
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
        val from = msg.from
        val body = msg.content as? Broadcast2 ?: return ErrInvalidContent

        try {
            if (!round1.paillier[from]!!.validateCiphertexts(body.k!!, body.g!!))
                return Exception("Invalid K, G")
        } catch (e: Exception) { return e}
        k[from] = body.k
        g[from] = body.g
        return null
    }

    override fun broadcastContent(): BroadcastContent? {
        return Broadcast2(
            k = null,
            g = null,
        )
    }

    override suspend fun verifyMessage(msg: Message): Exception? {
        val from = msg.from
        val body = msg.content as? Message2 ?: return IllegalArgumentException("Invalid content")

        val proofEnc = body.proofEnc ?: return IllegalArgumentException("Nil fields in proof")
        if (!proofEnc.verify(group(), helper.hashForID(from), Public(k[from]!!, round1.paillier[from]!!, round1.pedersen[selfID()]!!))) {
            return IllegalArgumentException("Failed to validate enc proof for K")
        }
        return null
    }

    override fun storeMessage(msg: Message): Exception? {
        return null
    }

    override suspend fun finalize(out: Channel<Message>): Pair<Session?, Exception?> {
        helper.broadcastMessage(out, Broadcast3(bigGammaShare[selfID()]!!))

        val hash = helper.hashForID(selfID())

        val otherIDs = helper.otherPartyIDs()
        val mtaOuts = helper.pool!!.parallelize(otherIDs.size) { i ->
            val j = otherIDs[i]

            val (deltaBeta, deltaD, deltaF, deltaProof) = proveAffG(group(), hash, gammaShare, bigGammaShare[selfID()]!!, k[j]!!,
                round1.secretPaillier!!, round1.paillier[j]!!, round1.pedersen[j]!!)
            val (chiBeta, chiD, chiF, chiProof) = proveAffG(group(), hash, makeInt(round1.secretECDSA!!), round1.ecdsa[selfID()]!!, k[j]!!,
                round1.secretPaillier, round1.paillier[j]!!, round1.pedersen[j]!!)

            val proof = perun_network.ecdsa_threshold.zk.logstar.Proof.newProof(group(), hash,
                perun_network.ecdsa_threshold.zk.logstar.Public(k[selfID()]!!,
                    bigGammaShare[selfID()]!!,
                    null,
                    round1.paillier[selfID()]!!, round1.pedersen[j]!!),
                perun_network.ecdsa_threshold.zk.logstar.Private(gammaShare, gNonce))

            val res = helper.sendMessage(out, Message3(deltaD, deltaF, deltaProof, chiD, chiF, chiProof, proof), j)
            mtaOut(res.exceptionOrNull() as Exception?, deltaBeta, chiBeta)
        }

        val deltaShareBetas = mutableMapOf<ID, BigInteger>()
        val chiShareBetas = mutableMapOf<ID, BigInteger>()

        mtaOuts.forEachIndexed { idx, mtaOut ->
            val j = otherIDs[idx]
            val mtaRaw = mtaOut as? mtaOut
            mtaRaw?.let {
                if (it.err != null) { return Pair(this, it.err) }
                deltaShareBetas[j] = it.deltaBeta!!
                chiShareBetas[j] = it.chiBeta!!
            }
        }

        return Sign3(this, helper, deltaShareBetas, chiShareBetas, mutableMapOf(), mutableMapOf()) to null
    }

    override fun messageContent(): Content? {
        return Message2()
    }

    override fun number(): Number {
        return Number(2u)
    }

    fun paillier() = round1.paillier

    fun pedersen() = round1.pedersen

    fun ecdsa() = round1.ecdsa

    fun secretPaillier() = round1.secretPaillier

    fun secretECDSA() = round1.secretECDSA

    fun message() = round1.message

    fun publicKey() = round1.publicKey
}

data class Broadcast2(
    val k: CipherText?,
    val g: CipherText?
) : ReliableBroadcastContent()

data class Message2(
    val proofEnc: perun_network.ecdsa_threshold.zk.enc.Proof? = null
) : Content {
    override fun roundNumber(): Number {
        return Number(2u)
    }
}


data class mtaOut (
    val err: Exception?,
    val deltaBeta: BigInteger?,
    val chiBeta: BigInteger?
)