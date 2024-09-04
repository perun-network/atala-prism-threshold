package perun_network.ecdsa_threshold.protocols.cmp.sign

import kotlinx.coroutines.channels.Channel
import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.internal.round.*
import perun_network.ecdsa_threshold.internal.round.Number
import perun_network.ecdsa_threshold.math.curve.Curve
import perun_network.ecdsa_threshold.math.curve.Point
import perun_network.ecdsa_threshold.math.curve.Scalar
import perun_network.ecdsa_threshold.math.curve.makeInt
import perun_network.ecdsa_threshold.math.sample.SecureRandomInputStream
import perun_network.ecdsa_threshold.math.sample.scalar
import perun_network.ecdsa_threshold.math.sample.scalarPointPair
import perun_network.ecdsa_threshold.party.ID
import perun_network.ecdsa_threshold.protocols.cmp.paillier.PublicKey
import perun_network.ecdsa_threshold.protocols.cmp.paillier.SecretKey
import perun_network.ecdsa_threshold.protocols.cmp.pedersen.Parameters
import perun_network.ecdsa_threshold.zk.enc.Proof.Companion.newProof
import perun_network.ecdsa_threshold.zk.enc.Public
import perun_network.ecdsa_threshold.zk.enc.Private
import java.security.SecureRandom

class Sign1(
    private val helper: Helper,

    val publicKey : Point,
    val secretECDSA: Scalar,
    val secretPaillier: SecretKey?,
    val paillier: MutableMap<ID, PublicKey>,
    val pedersen: MutableMap<ID, Parameters>,
    val ecdsa: MutableMap<ID, Point>,
    val message: ByteArray
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
        val (gammaShare, bigGammaShare) = scalarPointPair(SecureRandomInputStream(SecureRandom()), helper.group())
        val (g, gNonce) = paillier[helper.selfID()]?.enc(makeInt(gammaShare))!!

        val kShare = scalar(SecureRandomInputStream(SecureRandom()), helper.group())
        val kShareInt = makeInt(kShare)
        val (k, kNonce) = paillier[helper.selfID()]?.enc(kShareInt)!!

        val otherIDs = helper.otherPartyIDs()
        val broadcastMsg = Broadcast2(k, g)

        try {
            helper.broadcastMessage(out, broadcastMsg)
        } catch (e: Exception) {
            return Pair(helper.abortRound(e), e)
        }

        val hash = helper.hashForID(helper.selfID())

        helper.pool?.parallelize(otherIDs.size) { i ->
            val j = otherIDs[i]
            val proof = newProof(
                helper.group(),
                hash,
                Public(
                    k,
                    paillier[helper.selfID()]!!,
                    pedersen[j]!!
                ),
                Private(
                    kShareInt,
                    kNonce
                )
            )
            helper.sendMessage(out, Message2(proof), j)
        }?.forEach { err ->
            val result = err as Result<*>
            if (result.isFailure) {
                return Pair(
                    helper.abortRound(result.exceptionOrNull() as Exception),
                    result.exceptionOrNull() as Exception
                )
            }
        }

        return Sign2(
            this,
            helper,
            mutableMapOf(helper.selfID() to k),
            mutableMapOf(helper.selfID() to g),
            mutableMapOf(helper.selfID() to bigGammaShare),
            makeInt(gammaShare),
            kShare,
            kNonce,
            gNonce
        ) to null
    }

    override fun messageContent(): Content? {
        return null
    }

    override fun number(): Number {
        return Number(1u)
    }
}