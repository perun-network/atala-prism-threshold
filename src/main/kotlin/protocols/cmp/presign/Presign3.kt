package perun_network.ecdsa_threshold.protocols.cmp.presign

import kotlinx.coroutines.channels.Channel
import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.internal.elgamal.Ciphertext.Companion.encrypt
import perun_network.ecdsa_threshold.internal.mta.proveAffG
import perun_network.ecdsa_threshold.internal.mta.proveAffP
import perun_network.ecdsa_threshold.internal.round.*
import perun_network.ecdsa_threshold.internal.round.Number
import perun_network.ecdsa_threshold.internal.round.RoundErrors.ErrInvalidContent
import perun_network.ecdsa_threshold.internal.round.RoundErrors.ErrNilFields
import perun_network.ecdsa_threshold.math.curve.Curve
import perun_network.ecdsa_threshold.math.curve.makeInt
import perun_network.ecdsa_threshold.party.ID
import perun_network.ecdsa_threshold.protocols.cmp.paillier.CipherText
import java.math.BigInteger

class Presign3(
    private val presign2: Presign2,
    private val helper: Helper,
    val deltaShareBeta: MutableMap<ID, BigInteger>,
    val chiShareBeta: MutableMap<ID, BigInteger>,
    val deltaCiphertext: MutableMap<ID, MutableMap<ID, CipherText>>,
    val chiCiphertext: MutableMap<ID, MutableMap<ID, CipherText>>
) : Session, BroadcastRound {

    override fun group(): Curve {
        return presign2.group()
    }

    override suspend fun hash(): Hash {
        return presign2.hash()
    }

    override fun protocolID(): String {
        return presign2.protocolID()
    }

    override fun finalRoundNumber(): Number {
        return presign2.finalRoundNumber()
    }

    override fun ssid(): ByteArray {
        return presign2.ssid()
    }

    override fun selfID(): ID {
        return presign2.selfID()
    }

    override fun partyIDs(): List<ID> {
        return presign2.partyIDs()
    }

    override fun otherPartyIDs(): List<ID> {
        return presign2.otherPartyIDs()
    }

    override fun threshold(): Int {
        return presign2.threshold()
    }

    override fun n(): Int {
        return presign2.n()
    }

    override fun broadcastContent(): BroadcastContent? {
        return Broadcast3(mutableMapOf(), mutableMapOf())
    }

    override suspend fun storeBroadcastMessage(msg: Message): Exception? {
        val from = msg.from
        val body = msg.content as? Broadcast3 ?: return RoundErrors.ErrInvalidContent

        if (body.deltaCiphertext == null || body.chiCiphertext == null) {
            return RoundErrors.ErrNilFields
        }

        for (id in partyIDs()) {
            if (id == from) continue
            val deltaCiphertext = body.deltaCiphertext[id] ?: return RoundErrors.ErrInvalidContent
            val chiCiphertext = body.chiCiphertext[id] ?: return RoundErrors.ErrInvalidContent
            if (!presign2.presign1().paillier[id]!!.validateCiphertexts(deltaCiphertext, chiCiphertext)) {
                return Exception("received invalid ciphertext")
            }
        }

        deltaCiphertext[from] = body.deltaCiphertext
        chiCiphertext[from] = body.chiCiphertext
        return null
    }

    override suspend fun verifyMessage(msg: Message): Exception? {
        val from = msg.from
        val to = msg.to
        val body = msg.content as? Message3 ?: return RoundErrors.ErrInvalidContent

        if (!body.deltaProof!!.verify(group(), helper.hashForID(from), perun_network.ecdsa_threshold.zk.affp.Public(
                presign2.K[to] ?: return RoundErrors.ErrInvalidContent,
                deltaCiphertext[from]?.get(to) ?: return RoundErrors.ErrInvalidContent,
                body.deltaF ?: return ErrInvalidContent,
                presign2.G[from] ?: return RoundErrors.ErrInvalidContent,
                presign2.presign1().paillier[from] ?: return RoundErrors.ErrInvalidContent,
                presign2.presign1().paillier[to] ?: return RoundErrors.ErrInvalidContent,
                presign2.presign1().pedersen[to] ?: return RoundErrors.ErrInvalidContent
            ))) {
            return Exception("failed to validate affp proof for Delta MtA")
        }

        if (!body.chiProof!!.verify(helper.hashForID(from), perun_network.ecdsa_threshold.zk.affg.Public(
                 presign2.K[to] ?: return RoundErrors.ErrInvalidContent,
                chiCiphertext[from]?.get(to) ?: return RoundErrors.ErrInvalidContent,
                body.chiF ?: return ErrInvalidContent,
                presign2.presign1().ecdsa[from] ?: return RoundErrors.ErrInvalidContent,
                presign2.presign1().paillier[from] ?: return RoundErrors.ErrInvalidContent,
                presign2.presign1().paillier[to] ?: return RoundErrors.ErrInvalidContent,
                presign2.presign1().pedersen[to] ?: return RoundErrors.ErrInvalidContent
            ))) {
            return Exception("failed to validate affg proof for Chi MtA")
        }

        return null
    }

    override fun storeMessage(msg: Message): Exception? {
        return null
    }

    override suspend fun finalize(out: Channel<Message>): Pair<Session?, Exception?> {
        val kShareInt = makeInt(presign2.KShare)
        val deltaShare = BigInteger(presign2.GammaShare.toString()).multiply(kShareInt)

        val deltaSharesAlpha = mutableMapOf<ID, BigInteger>()
        val chiSharesAlpha = mutableMapOf<ID, BigInteger>()

        val chiShare = BigInteger(presign2.presign1().secretECDSA.toString()).multiply(kShareInt)

        val culprits = mutableListOf<ID>()
        for (j in otherPartyIDs()) {
            try {
                val deltaSharesAlphaJ = presign2.presign1().secretPaillier?.decrypt(deltaCiphertext[j]?.get(selfID())!!)
                deltaSharesAlpha[j] = deltaSharesAlphaJ!!

                val chiSharesAlphaJ = presign2.presign1().secretPaillier?.decrypt(chiCiphertext[j]?.get(selfID())!!)
                chiSharesAlpha[j] = chiSharesAlphaJ!!

                deltaShare.add(deltaSharesAlphaJ).add(deltaShareBeta[j])
                chiShare.add(chiSharesAlphaJ).add(chiShareBeta[j])

            } catch (e: Exception) {
                culprits.add(j)
            }
        }
        if (culprits.isNotEmpty()) {
            return helper.abortRound(Exception("failed to decrypt alpha shares for mta"), *culprits.toTypedArray()) to null
        }

        val (elGamalChi, elGamalChiNonce) = encrypt(presign2.presign1().elGamal[selfID()]!!, group().newScalar().setNat(chiShare.mod(group().order())))

        val deltaShareScalar = group().newScalar().setNat(deltaShare.mod(group().order()))

        val msg = Broadcast4(
            deltaShare = deltaShareScalar,
            elGamalChi = elGamalChi
        )

        val broadcastResult = helper.broadcastMessage(out, msg)
        if (broadcastResult.isFailure) {
            return this to broadcastResult.exceptionOrNull() as Exception
        }

        return Presign4(
            presign3 = this,
            helper = helper,
            deltaShareAlpha = deltaSharesAlpha,
            chiShareAlpha = chiSharesAlpha,
            elGamalChiNonce = elGamalChiNonce,
            elGamalChi = mutableMapOf(selfID() to elGamalChi),
            deltaShares = mutableMapOf(selfID() to deltaShareScalar),
            chiShare = group().newScalar().setNat(chiShare.mod(group().order()))
        ) to null
    }

    override fun messageContent(): Content? {
        return Message3(
            null,
            null,
            null,
            perun_network.ecdsa_threshold.zk.affg.Proof.empty(group()))
    }

    override fun number(): Number {
        return Number(3u)
    }

    fun presign2(): Presign2 = presign2
}

data class Broadcast3(
    val deltaCiphertext: MutableMap<ID, CipherText>?,
    val chiCiphertext: MutableMap<ID, CipherText>?
) : NormalBroadcastContent() {
    override fun roundNumber() = Number(3u)
}

data class Message3(
    val deltaF: CipherText?,
    val deltaProof: perun_network.ecdsa_threshold.zk.affp.Proof?,
    val chiF: CipherText?,
    val chiProof: perun_network.ecdsa_threshold.zk.affg.Proof?
) : Content {
    override fun roundNumber(): Number = Number(3u)
}