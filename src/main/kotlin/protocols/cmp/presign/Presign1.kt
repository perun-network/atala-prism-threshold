package perun_network.ecdsa_threshold.protocols.cmp.presign

import kotlinx.coroutines.channels.Channel
import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.internal.elgamal.Ciphertext.Companion.encrypt
import perun_network.ecdsa_threshold.internal.round.*
import perun_network.ecdsa_threshold.internal.round.Number
import perun_network.ecdsa_threshold.internal.types.RID.Companion.newRID
import perun_network.ecdsa_threshold.math.curve.Curve
import perun_network.ecdsa_threshold.math.curve.Point
import perun_network.ecdsa_threshold.math.curve.Scalar
import perun_network.ecdsa_threshold.math.curve.makeInt
import perun_network.ecdsa_threshold.math.sample.SecureRandomInputStream
import perun_network.ecdsa_threshold.math.sample.scalar
import perun_network.ecdsa_threshold.party.ID
import perun_network.ecdsa_threshold.pool.Pool
import perun_network.ecdsa_threshold.protocols.cmp.paillier.PublicKey
import perun_network.ecdsa_threshold.protocols.cmp.paillier.SecretKey
import perun_network.ecdsa_threshold.protocols.cmp.pedersen.Parameters
import perun_network.ecdsa_threshold.zk.encelg.Private
import perun_network.ecdsa_threshold.zk.encelg.Proof.Companion.newProof
import perun_network.ecdsa_threshold.zk.encelg.Public
import java.security.SecureRandom

class Presign1 (
    private val helper: Helper,
    private val pool : Pool?,
    val secretECDSA : Scalar?,
    val secretElGamal: Scalar?,
    val secretPaillier: SecretKey?,
    val publicKey: Point?,
    val ecdsa: MutableMap<ID, Point>,
    val elGamal: MutableMap<ID, Point> ,
    val paillier: MutableMap<ID, PublicKey>,
    val pedersen: MutableMap<ID, Parameters>,
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
        val gammaShare = scalar(SecureRandomInputStream(SecureRandom()), helper.group())
        val (g, gNonce) = paillier[helper.selfID()]?.enc(makeInt(gammaShare))!!

        val kShare = scalar(SecureRandomInputStream(SecureRandom()), helper.group())
        val kShareInt = makeInt(kShare)
        val (k, kNonce) = paillier[helper.selfID()]?.enc(kShareInt)!!

        val (elGamalK, elGamalNonce) = encrypt(elGamal[helper.selfID()]!!, kShare)

        val presignatureID = try {
            newRID(SecureRandom())
        } catch (e: Exception) {
            return Pair(helper.abortRound(e), e)
        }

        val (commitmentID, decommitmentID) = helper.hashForID(helper.selfID()).commit(presignatureID)

        val otherIDs = helper.otherPartyIDs()
        val broadcastMsg = Broadcast2(k, g, elGamalK, commitmentID)

        try {
            helper.broadcastMessage(out, broadcastMsg)
        } catch (e: Exception) {
            return Pair(helper.abortRound(e), e)
        }

        val hash = helper.hashForID(helper.selfID())

        pool?.parallelize(otherIDs.size) { i ->
            val j = otherIDs[i]
            val proof = newProof(
                helper.group(),
                hash,
                Public(
                    k,
                    elGamal[helper.selfID()]!!,
                    elGamalK.l,
                    elGamalK.m,
                    paillier[helper.selfID()]!!,
                    pedersen[j]!!
                ),
                Private(
                    kShareInt,
                    kNonce,
                    secretElGamal!!,
                    elGamalNonce
                )
            )
            helper.sendMessage(out, Message2(proof), j)
        }?.forEach { err ->
            val result = err as Result<UInt>
            if (result.isFailure) {
                return Pair(
                    helper.abortRound(result.exceptionOrNull() as Exception),
                    result.exceptionOrNull() as Exception
                )
            }
        }

        return Presign2(
            this,
            helper,
            mutableMapOf(helper.selfID() to k),
            mutableMapOf(helper.selfID() to g),
            makeInt(gammaShare),
            kShare,
            kNonce,
            gNonce,
            elGamalNonce,
            mutableMapOf(helper.selfID() to elGamalK),
            mutableMapOf(helper.selfID() to presignatureID),
            mutableMapOf(),
            decommitmentID
        ) to null
    }

    override fun messageContent(): Content? {
        return null
    }

    override fun number(): Number {
        return Number(1u)
    }

}