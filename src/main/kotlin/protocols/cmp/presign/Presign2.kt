package perun_network.ecdsa_threshold.protocols.cmp.presign

import kotlinx.coroutines.channels.Channel
import perun_network.ecdsa_threshold.hash.*
import perun_network.ecdsa_threshold.internal.elgamal.Ciphertext
import perun_network.ecdsa_threshold.internal.elgamal.Ciphertext.Companion.empty
import perun_network.ecdsa_threshold.internal.elgamal.Nonce
import perun_network.ecdsa_threshold.internal.mta.proveAffG
import perun_network.ecdsa_threshold.internal.mta.proveAffP
import perun_network.ecdsa_threshold.internal.round.*
import perun_network.ecdsa_threshold.internal.round.Number
import perun_network.ecdsa_threshold.internal.round.RoundErrors.ErrInvalidContent
import perun_network.ecdsa_threshold.internal.round.RoundErrors.ErrNilFields
import perun_network.ecdsa_threshold.math.curve.Scalar
import perun_network.ecdsa_threshold.math.curve.makeInt
import perun_network.ecdsa_threshold.party.ID
import perun_network.ecdsa_threshold.internal.types.RID
import perun_network.ecdsa_threshold.math.curve.Curve
import perun_network.ecdsa_threshold.protocols.cmp.paillier.CipherText
import perun_network.ecdsa_threshold.zk.encelg.Proof
import perun_network.ecdsa_threshold.zk.encelg.Public
import java.math.BigInteger

class Presign2 (
    private val presign1: Presign1,
    private val helper: Helper,

    val K: MutableMap<ID, CipherText>,
    val G: MutableMap<ID, CipherText>,
    val GammaShare: BigInteger,
    val KShare: Scalar,
    val KNonce: BigInteger,
    val GNonce: BigInteger,
    val ElGamalKNonce: Nonce,
    val ElGamalK: MutableMap<ID, Ciphertext>,
    val PresignatureID: MutableMap<ID, RID>,
    val CommitmentID: MutableMap<ID, Commitment>,
    val DecommitmentID: Decommitment
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
        val body : Broadcast2 = msg.content as? Broadcast2 ?: return ErrInvalidContent

        if (!(body.K?.let { body.G?.let { it1 -> presign1.paillier[from]?.validateCiphertexts(it, it1) } } ?: return ErrInvalidContent) ||
                !body.Z.valid()) {
            return ErrNilFields
        }

        val err =  body.commitmentID?.validate()
        if (err != null) {
            return err
        }

        K[from] = body.K
        G[from] = body.G!!
        ElGamalK[from] = body.Z
        CommitmentID[from] = body.commitmentID!!

        return null
    }

    override fun broadcastContent(): BroadcastContent? {
        return Broadcast2(
            K = null,
            G = null,
            Z = empty(helper.group()),
            commitmentID = null
        )
    }

    override suspend fun verifyMessage(msg: Message): Exception? {
        val from = msg.from
        val to = msg.to
        val body = msg.content as? Message2 ?: return ErrInvalidContent

        val public = Public(
            c = K[from] ?: return ErrInvalidContent,
            a = presign1.elGamal[from] ?: return ErrInvalidContent,
            b = ElGamalK[from]?.l ?: return ErrInvalidContent,
            x = ElGamalK[from]?.m ?: return ErrInvalidContent,
            prover = presign1.paillier[from] ?: return ErrInvalidContent,
            aux = presign1.pedersen[to] ?: return ErrInvalidContent
        )

        val  hash = helper.hashForID(from)

        if (!body.proof.verify(hash, public)) {
            return Exception("Failed to validate enc-elg proof for K")
        }
        return null
    }

    override fun storeMessage(msg: Message): Exception? {
        return null
    }

    override suspend fun finalize(out: Channel<Message>): Pair<Session?, Exception?> {
        val otherIDs = otherPartyIDs()
        val n = otherIDs.size



        val selfID = selfID()
        val hash = helper.hashForID(selfID)

        val mtaOuts = helper.pool?.parallelize(n) { i ->
            val j = otherIDs[i]



            val (deltaBeta, deltaD, deltaF, deltaProof) = proveAffP(
                 group(),
                 hash,
                 GammaShare,
                 G[helper.selfID()] ?: throw IllegalStateException("G[selfID] is null"),
                 GNonce,
                 K[j] ?: throw IllegalStateException("K[j] is null"),
                 presign1.secretPaillier!!,
                 presign1.paillier[j] ?: throw IllegalStateException("Paillier[j] is null"),
                 presign1.pedersen[j] ?: throw IllegalStateException("Pedersen[j] is null")
            )

            val (chiBeta, chiD, chiF, chiProof) = proveAffG(
                group(),
                hash,
                makeInt(presign1.secretECDSA!!),
                presign1.ecdsa[selfID] ?: throw IllegalStateException("ECDSA[selfID] is null"),
                K[j] ?: throw IllegalStateException("K[j] is null"),
                presign1.secretPaillier!!,
                presign1.paillier[j] ?: throw IllegalStateException("Paillier[j] is null"),
                presign1.pedersen[j] ?: throw IllegalStateException("Pedersen[j] is null")
            )

            mtaOut(deltaBeta, deltaD, deltaF, deltaProof, chiBeta, chiD, chiF, chiProof) to null
        }

        val chiCiphertext = mutableMapOf<ID, CipherText>()
        val deltaCiphertext = mutableMapOf<ID, CipherText>()
        val deltaShareBeta = mutableMapOf<ID, BigInteger>()
        val chiShareBeta = mutableMapOf<ID, BigInteger>()

        val broadcastMsg = Broadcast3(
            deltaCiphertext = deltaCiphertext,
            chiCiphertext = chiCiphertext
        )

        val msgs = mutableMapOf<ID, Message3>()
        for ((idx, mtaOut) in mtaOuts!!.withIndex()) {
            val j = otherIDs[idx]
            val mta = mtaOut as mtaOut
            deltaShareBeta[j] = mta.DeltaBeta!!
            deltaCiphertext[j] = mta.DeltaD!!
            chiShareBeta[j] = mta.ChiBeta!!
            chiCiphertext[j] = mta.ChiD!!
            msgs[j] = Message3(
                deltaF = mta.DeltaF,
                deltaProof = mta.DeltaProof,
                chiF = mta.ChiF,
                chiProof = mta.ChiProof
            )
        }

        val broadcastResult = helper.broadcastMessage(out, broadcastMsg)
        if (broadcastResult.isFailure) {
            return this to broadcastResult.exceptionOrNull() as Exception
        }

        for ((id, msg) in msgs) {
            val sendMessageResult = helper.sendMessage(out, msg, id)
            if ( sendMessageResult.isFailure) {
                return this to sendMessageResult.exceptionOrNull() as Exception
            }
        }

        return Presign3(
            presign2 = this,
            helper = helper,
            deltaShareBeta = deltaShareBeta,
            chiShareBeta = chiShareBeta,
            deltaCiphertext = mutableMapOf(selfID to deltaCiphertext),
            chiCiphertext = mutableMapOf(selfID to chiCiphertext)
        ) to null
    }

    override fun messageContent(): Content? {
        return Message2(
            proof = Proof.empty(group())
        )
    }

    override fun number(): Number {
        return Number(2u)
    }

    fun presign1() : Presign1 {
        return presign1
    }
}

data class Broadcast2(
    val K: CipherText?,
    val G: CipherText?,
    val Z: Ciphertext,
    val commitmentID: Commitment?
) : ReliableBroadcastContent() {
    override fun roundNumber() = Number(2u)
}

data class Message2(
    val proof: Proof
) : Content {
    override fun roundNumber() = Number(2u)
}

data class mtaOut (
    val DeltaBeta: BigInteger?,
    val DeltaD: CipherText?,
    val DeltaF: CipherText?,
    val DeltaProof: perun_network.ecdsa_threshold.zk.affp.Proof?,
    val ChiBeta: BigInteger?,
    val ChiD: CipherText?,
    val ChiF: CipherText?,
    val ChiProof: perun_network.ecdsa_threshold.zk.affg.Proof?
)