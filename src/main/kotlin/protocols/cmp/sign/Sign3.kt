package perun_network.ecdsa_threshold.protocols.cmp.sign

import kotlinx.coroutines.channels.Channel
import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.internal.round.*
import perun_network.ecdsa_threshold.internal.round.Number
import perun_network.ecdsa_threshold.internal.round.RoundErrors.ErrInvalidContent
import perun_network.ecdsa_threshold.internal.round.RoundErrors.ErrNilFields
import perun_network.ecdsa_threshold.math.curve.Curve
import perun_network.ecdsa_threshold.math.curve.Point
import perun_network.ecdsa_threshold.math.curve.makeInt
import perun_network.ecdsa_threshold.party.ID
import perun_network.ecdsa_threshold.protocols.cmp.paillier.CipherText
import perun_network.ecdsa_threshold.zk.affg.Public
import perun_network.ecdsa_threshold.zk.logstar.Proof
import java.math.BigInteger
import kotlin.math.round

class Sign3 (
    private val round2: Sign2,
    private val helper: Helper,

    val deltaShareAlpha: MutableMap<ID, BigInteger>,
    val deltaShareBeta: MutableMap<ID, BigInteger>,
    val chiShareAlpha: MutableMap<ID, BigInteger>,
    val chiShareBeta: MutableMap<ID, BigInteger>,
) : Session, BroadcastRound {
    override fun group(): Curve = helper.group()

    override suspend fun hash(): Hash = helper.hash()

    override fun protocolID(): String = helper.protocolID()

    override fun finalRoundNumber(): Number = helper.finalRoundNumber()

    override fun ssid(): ByteArray = helper.ssid()

    override fun selfID(): ID = helper.selfID()

    override fun partyIDs(): List<ID> = helper.partyIDs()

    override fun otherPartyIDs(): List<ID> = helper.otherPartyIDs()

    override fun threshold(): Int = helper.threshold()

    override fun n(): Int = helper.n()

    override suspend fun storeBroadcastMessage(msg: Message): Exception? {
        val body = msg.content as? Broadcast3 ?: return ErrInvalidContent
        if (body.bigGammaShare.isIdentity()) {
            return ErrNilFields
        }
        round2.bigGammaShare[msg.from] = body.bigGammaShare
        return null
    }

    override fun broadcastContent(): BroadcastContent? {
        return Broadcast3(
            bigGammaShare = group().newPoint()
        )
    }

    override suspend fun verifyMessage(msg: Message): Exception? {
        val from = msg.from
        val to = msg.to
        val body = msg.content as? Message3 ?: return ErrInvalidContent

        val deltaProof = body.deltaProof ?: return ErrNilFields
        val chiProof = body.chiProof ?: return ErrNilFields
        val proofLog = body.proofLog ?: return ErrNilFields

        // Prepare public parameters for DeltaProof verification
        val paillierFrom = round2.paillier()[from]
            ?: return IllegalArgumentException("Missing Paillier key for $from")
        val paillierTo = round2.paillier()[to]
            ?: return IllegalArgumentException("Missing Paillier key for $to")
        val pedersenTo = round2.pedersen()[to]
            ?: return IllegalArgumentException("Missing Pedersen parameters for $to")
        val kTo = round2.k[to]
            ?: return IllegalArgumentException("Missing K for $to")
        val bigGammaShareFrom = round2.bigGammaShare[from]
            ?: return IllegalArgumentException("Missing BigGammaShare for $from")
        val ecdsaFrom = round2.ecdsa()[from]
            ?: return IllegalArgumentException("Missing ECDSA for $from")
        val gSelf = round2.g[selfID()]
            ?: return IllegalArgumentException("Missing G for self ID")

        val zkaffgPublicDelta = Public(
            kv = kTo,
            dv = body.deltaD!!,
            fp = body.deltaF!!,
            xp = bigGammaShareFrom,
            prover = paillierFrom,
            verifier = paillierTo,
            aux = pedersenTo
        )

        // Verify DeltaProof
        if (!deltaProof.verify(helper.hashForID(from), zkaffgPublicDelta)) {
            return IllegalArgumentException("Failed to validate affg proof for Delta MtA")
        }

        // Prepare public parameters for ChiProof verification
        val zkaffgPublicChi = Public(
            kv = kTo,
            dv = body.chiD!!,
            fp = body.chiF!!,
            xp = ecdsaFrom,
            prover = paillierFrom,
            verifier = paillierTo,
            aux = pedersenTo
        )

        // Verify ChiProof
        if (!chiProof.verify(helper.hashForID(from), zkaffgPublicChi)) {
            return IllegalArgumentException("Failed to validate affg proof for Chi MtA")
        }

        // Prepare public parameters for ProofLog verification
        val zklogstarPublic = perun_network.ecdsa_threshold.zk.logstar.Public(
            c = gSelf,
            x = round2.bigGammaShare[from]!!,
            prover = paillierFrom,
            aux = pedersenTo,
            g = null
        )

        // Verify ProofLog
        if (!proofLog.verify(helper.hashForID(from), zklogstarPublic)) {
            return IllegalArgumentException("Failed to validate log proof")
        }

        return null
    }

    override fun storeMessage(msg: Message): Exception? {
        val from = msg.from
        val body = msg.content as? Message3 ?: return ErrInvalidContent

        // Decrypt DeltaD to get DeltaShareAlpha
        try {
            val decryptedDeltaAlpha = round2.secretPaillier()!!.decrypt(body.deltaD!!)
            // Decrypt ChiD to get ChiShareAlpha
            val decryptedChiAlpha = round2.secretPaillier()!!.decrypt(body.chiD!!)

            // Store the decrypted shares
            deltaShareAlpha[from] = decryptedDeltaAlpha // Assuming conversion from saferith.Int to Int
            chiShareAlpha[from] = decryptedChiAlpha
        } catch (exc : Exception) {return exc}
        return null
    }

    override suspend fun finalize(out: Channel<Message>): Pair<Session?, Exception?> {
        // Compute Γ = ∑ⱼ Γⱼ
        var gamma = helper.group().newPoint()
        for (bigGammaShare in round2.bigGammaShare.values) {
            gamma = gamma.add(bigGammaShare)
        }

        // Compute Δᵢ = [kᵢ]Γ
        val kShareInt = makeInt(round2.kShare)
        val bigDeltaShare = round2.kShare.act(gamma)

        // Compute δᵢ = γᵢ kᵢ - ∑ⱼ (αᵢⱼ + βᵢⱼ)
        var deltaShareInt = round2.gammaShare.multiply(kShareInt)
        for (j in helper.otherPartyIDs()) {
            val alpha = deltaShareAlpha[j] ?: BigInteger.ZERO
            val beta = deltaShareBeta[j] ?: BigInteger.ZERO
            deltaShareInt = deltaShareInt.add(alpha)
            deltaShareInt = deltaShareInt.add(beta)
        }

        // Compute χᵢ = xᵢ kᵢ - ∑ⱼ (α̂ᵢⱼ + β̂ᵢⱼ)
        var chiShareInt = makeInt(round2.secretECDSA()).multiply(kShareInt)
        for (j in helper.otherPartyIDs()) {
            val chiAlpha = chiShareAlpha[j] ?: BigInteger.ZERO
            val chiBeta = chiShareBeta[j] ?: BigInteger.ZERO
            chiShareInt = chiShareInt.add(chiAlpha)
            chiShareInt = chiShareInt.add(chiBeta)
        }

        // Convert δᵢ and χᵢ to Scalars modulo group order
        val deltaShareScalar = helper.group().newScalar().setNat(deltaShareInt.mod(helper.group().order()))
        val chiShareScalar = helper.group().newScalar().setNat(chiShareInt.mod(helper.group().order()))

        // Broadcast Δᵢ and Δᵢ
        val broadcast4 = Broadcast4(
            deltaShare = deltaShareScalar,
            bigDeltaShare = bigDeltaShare
        )
        try {
            helper.broadcastMessage(out, broadcast4)
        } catch (e: Exception) {
            return Pair(this, e)
        }

        // Prepare ProofLog
        val zkPrivate = perun_network.ecdsa_threshold.zk.logstar.Private(
            x = kShareInt,
            rho = round2.kNonce
        )

        val hash = helper.hashForID(selfID())

        // Send ProofLog to all other parties in parallel
        val otherIDs = helper.otherPartyIDs()
        val sendResults = helper.pool!!.parallelize(otherIDs.size) { i ->
            val j = otherIDs[i]
            try {
                val proofLog = perun_network.ecdsa_threshold.zk.logstar.Proof.newProof(
                    group = helper.group(),
                    hash = hash,
                    public = perun_network.ecdsa_threshold.zk.logstar.Public(
                        c = round2.g[selfID()]!!,
                        x = bigDeltaShare,
                        g = gamma,
                        prover = round2.paillier()[selfID()]!!,
                        aux = round2.pedersen()[j]!!
                    ),
                    private = zkPrivate
                )
                helper.sendMessage(out, Message4(proofLog), j)
                null
            } catch (e: Exception) {
                e
            }
        }

        // Check for any errors during sending
        for (res in sendResults) {
            val sendRes = res as Result<*>
            if (sendRes.isFailure) {
                return Pair(this, sendRes.exceptionOrNull() as Exception)
            }
        }

        // Transition to round4
        val round4 = Sign4(
            round3 = this,
            helper = helper,
            deltaShares = mutableMapOf(helper.selfID() to deltaShareScalar),
            bigDeltaShares = mutableMapOf(helper.selfID() to bigDeltaShare),
            gamma = gamma,
            chiShare = chiShareScalar
        )
        return Pair(round4, null)
    }

    override fun messageContent(): Content? {
        return Message3(
            proofLog = Proof.empty(group()),
            deltaProof = perun_network.ecdsa_threshold.zk.affg.Proof.empty(group()),
            chiProof = perun_network.ecdsa_threshold.zk.affg.Proof.empty(group())
        )
    }

    override fun number(): Number {
        return Number(3u)
    }

    fun k() = round2.k

    fun paillier() = round2.paillier()

    fun pedersen() = round2.pedersen()

    fun message() = round2.message()

    fun kShare() = round2.kShare

    fun publicKey() = round2.publicKey()
}

// Data classes representing the messages and broadcasts for round3
data class Broadcast3(
    val bigGammaShare: Point
) : NormalBroadcastContent() {
    override fun roundNumber(): Number = Number(3u)
}

data class Message3(
    val deltaD: CipherText? = null,
    val deltaF: CipherText? = null,
    val deltaProof: perun_network.ecdsa_threshold.zk.affg.Proof? = null,
    val chiD: CipherText? = null,
    val chiF: CipherText? = null,
    val chiProof: perun_network.ecdsa_threshold.zk.affg.Proof? = null,
    val proofLog: perun_network.ecdsa_threshold.zk.logstar.Proof? = null
) : Content {
    override fun roundNumber(): Number = Number(3u)
}