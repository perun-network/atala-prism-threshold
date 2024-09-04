package perun_network.ecdsa_threshold.protocols.cmp.keygen

import kotlinx.coroutines.channels.Channel
import perun_network.ecdsa_threshold.hash.Decommitment
import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.internal.round.*
import perun_network.ecdsa_threshold.internal.round.Number
import perun_network.ecdsa_threshold.internal.round.RoundErrors.ErrInvalidContent
import perun_network.ecdsa_threshold.internal.round.RoundErrors.ErrNilFields
import perun_network.ecdsa_threshold.internal.types.RID
import perun_network.ecdsa_threshold.math.curve.Curve
import perun_network.ecdsa_threshold.math.curve.Point
import perun_network.ecdsa_threshold.math.curve.Scalar
import perun_network.ecdsa_threshold.math.curve.makeInt
import perun_network.ecdsa_threshold.math.polynomial.Exponent
import perun_network.ecdsa_threshold.party.ID
import perun_network.ecdsa_threshold.protocols.cmp.paillier.PublicKey
import perun_network.ecdsa_threshold.protocols.cmp.paillier.PublicKey.Companion.newPublicKey
import perun_network.ecdsa_threshold.protocols.cmp.paillier.PublicKey.Companion.validateN
import perun_network.ecdsa_threshold.protocols.cmp.paillier.SecretKey
import perun_network.ecdsa_threshold.protocols.cmp.pedersen.Parameters
import perun_network.ecdsa_threshold.protocols.cmp.pedersen.Parameters.Companion.validateParameters
import perun_network.ecdsa_threshold.zk.mod.Private
import perun_network.ecdsa_threshold.zk.mod.Public
import perun_network.ecdsa_threshold.zk.mod.newProof
import perun_network.ecdsa_threshold.zk.schnorr.Commitment
import perun_network.ecdsa_threshold.zk.schnorr.Randomness
import perun_network.ecdsa_threshold.zk.schnorr.emptyCommitment
import java.math.BigInteger

class Round3 (
    private val previousRound: Round2,
    private val helper: Helper,
    val schnorrCommitments: MutableMap<ID, Commitment>
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
        val body = msg.content as? Broadcast3 ?: return ErrInvalidContent

        // Validation
        body.n ?: return ErrNilFields
        body.s ?: return ErrNilFields
        body.t ?: return ErrNilFields
        body.vssPolynomial ?: return ErrNilFields
        body.schnorrCommitments ?: return ErrNilFields

        body.rid?.let {
            if (it.validate()) return IllegalArgumentException("Invalid RID")
        } ?: return ErrNilFields

        body.chainKey?.let {
            if (it.validate()) return IllegalArgumentException("Invalid ChainKey")
        } ?: return ErrNilFields

        body.decommitment?.let {
            if (it.validate()) return IllegalArgumentException("Invalid Decommitment")
        } ?: return ErrNilFields

        // Save all VSSCommitments
        val vssPolynomial = body.vssPolynomial
        if (vssPolynomial.isConstant != (previousRound.vssSecret()?.constant()?.isZero() ?: return ErrNilFields)) {
            return IllegalStateException("VSS polynomial has incorrect constant")
        }

        if (vssPolynomial.degree() != previousRound.threshold()) {
            return IllegalStateException("VSS polynomial has incorrect degree")
        }

        if (validateN(body.n) != null) return IllegalArgumentException("Invalid Paillier modulus")
        if (validateParameters(body.n, body.s, body.t) != null ) return IllegalArgumentException("Invalid Pedersen parameters")

        if (!body.elGamalPublic?.let {
                helper.hashForID(msg.from).decommit(
                    previousRound.commitments[msg.from] ?: return IllegalArgumentException("Missing commitment"),
                    body.decommitment,
                    body.rid,
                    body.chainKey,
                    vssPolynomial,
                    body.schnorrCommitments,
                    it,
                    body.n,
                    body.s,
                    body.t
                )
            }!!
        ) {
            return IllegalArgumentException("Failed to decommit")
        }

        previousRound.rids[msg.from] = body.rid
        previousRound.chainKeys[msg.from] = body.chainKey
        previousRound.paillierPublic[msg.from] = newPublicKey(body.n)
        previousRound.pedersen[msg.from] = Parameters(body.n, body.s, body.t)
        previousRound.vssPolynomials[msg.from] = body.vssPolynomial
        schnorrCommitments[msg.from] = body.schnorrCommitments
        previousRound.elGamalPublic[msg.from] = body.elGamalPublic

        return null
    }

    override fun broadcastContent(): BroadcastContent? {
        return Broadcast3(
            vssPolynomial = Exponent.emptyExponent(group()),
            schnorrCommitments = emptyCommitment(group()),
            elGamalPublic = group().newPoint()
        )
    }

    override suspend fun verifyMessage(msg: Message): Exception? {
        return null
    }

    override fun storeMessage(msg: Message): Exception? {
        return null
    }

    override suspend fun finalize(out: Channel<Message>): Pair<Session?, Exception?> {
        var chainKey = previousRound.previousChainKey()
        if (chainKey == null) {
            chainKey = RID.emptyRID()
            previousRound.partyIDs().forEach { id ->
                chainKey!!.xor(previousRound.chainKeys[id]!!)
            }
        }

        val rid = RID.emptyRID()
        previousRound.partyIDs().forEach { id ->
            rid.xor(previousRound.rids[id]!!)
        }

        val h = previousRound.hash()
        h.writeAny(rid, previousRound.selfID())

        val mod = newProof(
            h.clone(),
            Private(
                previousRound.paillierSecret.p,
                previousRound.paillierSecret.q,
                previousRound.paillierSecret.phi
            ),
            Public(
                previousRound.paillierPublic[previousRound.selfID()]!!.modulus()
            ),
            helper.pool!!
        )

        val prm = helper.pool?.let {
            perun_network.ecdsa_threshold.zk.prm.newProof(
                perun_network.ecdsa_threshold.zk.prm.Private(
                    previousRound.pedersenSecret,
                    previousRound.paillierSecret.phi,
                    previousRound.paillierSecret.p,
                    previousRound.paillierSecret.q
                ),
                h.clone(),
                perun_network.ecdsa_threshold.zk.prm.Public(
                    previousRound.pedersen[previousRound.selfID()]!!
                ),
                it
            )
        }

        val sendResult = helper.broadcastMessage(
            out, Broadcast4(mod, prm!!)
        )
        if (sendResult.isFailure) {
            return Pair(previousRound, sendResult.exceptionOrNull() as Exception)
        }

        previousRound.otherPartyIDs().forEach { j ->
            val fac = perun_network.ecdsa_threshold.zk.fac.newProof(
                perun_network.ecdsa_threshold.zk.fac.Private(
                    previousRound.paillierSecret.p,
                    previousRound.paillierSecret.q
                ),
                h.clone(),
                perun_network.ecdsa_threshold.zk.fac.Public(
                    previousRound.paillierPublic[previousRound.selfID()]!!.modulus(),
                    previousRound.pedersen[j]!!
                )
            )

            val share = previousRound.vssSecret()!!.evaluate(j.scalar(previousRound.group()))
            val c = previousRound.paillierPublic[j]!!.enc(makeInt(share))

            val sendMessageResult = helper.sendMessage(
                out, Message4(c.first, fac), j
            )
            if (sendMessageResult.isFailure) {
                return Pair(previousRound, sendMessageResult.exceptionOrNull() as Exception)
            }
        }

        helper.updateHashState(rid)
        return Pair(Round4(this, helper, rid, chainKey), null)
    }

    override fun messageContent(): Content? {
        return null
    }

    override fun number(): Number {
        return Number(3.toUShort())
    }

    fun pedersen() : Map<ID, Parameters> {
        return previousRound.pedersen
    }

    fun paillierPublic() : Map<ID, PublicKey> {
        return previousRound.paillierPublic
    }

    fun paillierSecret() : SecretKey {
        return previousRound.paillierSecret
    }

    fun elGamalPublic() : MutableMap<ID, Point> {
        return previousRound.elGamalPublic
    }

    fun elGamalSecret() : Scalar {
        return previousRound.elGamalSecret
    }

    fun vssPolynomials(): Map<ID, Exponent> {
        return previousRound.vssPolynomials
    }

    fun shareReceived(): Map<ID, Scalar> {
        return previousRound.shareReceived
    }

    fun setShareReceived(id: ID, scalar: Scalar) {
        previousRound.shareReceived[id] = scalar
    }

    fun previousSecretECDSA () : Scalar? {
        return previousRound.previousSecretECDSA()
    }

    fun previousPublicSharesECDSA () : MutableMap<ID, Point> {
        return previousRound.previousPublicSharesECDSA()
    }

    fun schnorrRand() : Randomness {
        return previousRound.schnorrRand
    }
}

class Broadcast3 (
    val rid: RID? = null,
    val chainKey: RID? = null,
    val vssPolynomial: Exponent? = null,
    val schnorrCommitments: Commitment? = null,
    val elGamalPublic: Point? = null,
    val n: BigInteger? = null,
    val s: BigInteger? = null,
    val t: BigInteger? = null,
    val decommitment: Decommitment? = null
) : NormalBroadcastContent() {
    override fun roundNumber(): Number {
        return Number(3.toUShort())
    }
}