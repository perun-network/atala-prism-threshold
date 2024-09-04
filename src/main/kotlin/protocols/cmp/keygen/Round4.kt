package perun_network.ecdsa_threshold.protocols.cmp.keygen

import kotlinx.coroutines.channels.Channel
import perun_network.ecdsa_threshold.hash.Decommitment
import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.internal.round.*
import perun_network.ecdsa_threshold.internal.round.Number
import perun_network.ecdsa_threshold.internal.round.RoundErrors.ErrInvalidContent
import perun_network.ecdsa_threshold.internal.types.RID
import perun_network.ecdsa_threshold.math.curve.Curve
import perun_network.ecdsa_threshold.math.curve.Point
import perun_network.ecdsa_threshold.math.polynomial.Exponent
import perun_network.ecdsa_threshold.math.curve.makeInt
import perun_network.ecdsa_threshold.math.polynomial.Exponent.Companion.sum
import perun_network.ecdsa_threshold.party.ID
import perun_network.ecdsa_threshold.protocols.cmp.config.Config
import perun_network.ecdsa_threshold.protocols.cmp.paillier.CipherText
import perun_network.ecdsa_threshold.zk.fac.verify
import perun_network.ecdsa_threshold.zk.mod.verify
import perun_network.ecdsa_threshold.zk.prm.verify
import perun_network.ecdsa_threshold.protocols.cmp.config.Public
import perun_network.ecdsa_threshold.zk.schnorr.Commitment

class Round4 (
    private val previousRound : Round3,
    private val helper : Helper,
    val rid: RID,
    val chainKey: RID
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
        val body = msg.content as? Broadcast4 ?: return ErrInvalidContent

        // Verify zkmod proof
        try {
            if (!body.mod!!.verify(
                    perun_network.ecdsa_threshold.zk.mod.Public(
                        previousRound.pedersen()[from]!!.n()
                    ),
                    helper.hashForID(from),
                    helper.pool!!
                )
            ) {
                return Exception("Failed to validate mod proof")
            }

            // Verify zkprm proof
            if (!body.prm!!.verify(
                    perun_network.ecdsa_threshold.zk.prm.Public(
                        previousRound.pedersen()[from]!!
                    ),
                    helper.hashForID(from),
                    helper.pool
                )
            ) {
                return Exception("Failed to validate prm proof")
            }
        }
        catch (e: Exception) {
            return e
        }
        return null
    }


    override fun broadcastContent(): BroadcastContent? {
        return Broadcast4()
    }

    override suspend fun verifyMessage(msg: Message): Exception? {
        val from = msg.from
        val body = msg.content as? Message4 ?: return ErrInvalidContent

        try {
            // Verify share ciphertext
            if (!previousRound.paillierPublic()[msg.to]?.validateCiphertexts(body.share!!)!!) {
                return Exception("Invalid ciphertext")
            }

            // Verify zkfac proof
            if (!body.fac!!.verify(perun_network.ecdsa_threshold.zk.fac.Public(
                    previousRound.paillierPublic()[from]!!.modulus(),
                    previousRound.pedersen()[msg.to]!!),
                    helper.hashForID(from))) {
                return Exception("Failed to validate fac proof")
            }
        } catch (e: Exception) {
            return e
        }

        return null
    }

    override fun storeMessage(msg: Message): Exception? {
        val from = msg.from
        val body = msg.content as Message4

        try {
            // Decrypt share
            val decryptedShare = previousRound.paillierSecret().decrypt(body.share!!)
            val share = group().newScalar().setNat(decryptedShare.mod(group().order()))
            if (decryptedShare.equals(makeInt(share))) {
                return Exception("Decrypted share is not in the correct range")
            }

            // Verify share with VSS
            val expectedPublicShare = previousRound.vssPolynomials()[from]!!.evaluate(selfID().scalar(group()))
            val publicShare = share.actOnBase()

            if (!publicShare.equals(expectedPublicShare)) {
                return Exception("Failed to validate VSS share")
            }

            previousRound.setShareReceived(from, share)
            return null
        } catch (e: Exception) {
            return e
        }
    }

    override suspend fun finalize(out: Channel<Message>): Pair<Session?, Exception?> {
        try {
            // Add all shares to our secret
            var updatedSecretECDSA = group().newScalar()
            previousRound.previousSecretECDSA()?.let { updatedSecretECDSA.set(it) }

            partyIDs().forEach { j ->
                updatedSecretECDSA = updatedSecretECDSA.add(previousRound.shareReceived()[j]!!)
            }

            // Sum of all VSS polynomials
            val shamirPublicPolynomials = mutableListOf<Exponent>()
            previousRound.vssPolynomials().values.forEach { shamirPublicPolynomials.add(it) }
            val shamirPublicPolynomial = sum(shamirPublicPolynomials)

            // Compute new public key share
            val publicData = mutableMapOf<ID, Public>()
            partyIDs().forEach { j ->
                var publicECDSAShare = shamirPublicPolynomial.evaluate(j.scalar(group()))
                previousRound.previousPublicSharesECDSA().let {
                    publicECDSAShare = publicECDSAShare.add(it[j]!!)
                }
                publicData[j] = Public(
                    ecdsa = publicECDSAShare,
                    elGamal = previousRound.elGamalPublic()[j]!!,
                    paillier = previousRound.paillierPublic()[j],
                    pedersen = previousRound.pedersen()[j]
                )
            }

            // Update config with new SSID
            val updatedConfig = Config(
                group = group(),
                id = selfID(),
                threshold = threshold(),
                ecdsa = updatedSecretECDSA,
                elGamal = previousRound.elGamalSecret(),
                paillier = previousRound.paillierSecret(),
                rid = rid.copy(),
                chainKey = chainKey.copy(),
                public = publicData
            )

            // Write SSID to hash to bind Schnorr proof to this new config
            val h = hash()
            h.writeAny(updatedConfig, selfID())

            val proof = previousRound.schnorrRand().prove(h, publicData[selfID()]?.ecdsa!!, updatedSecretECDSA, null)

            // Send to all
            val res = helper.broadcastMessage(out, Broadcast5(proof))
            if (res.isFailure) {
                return this to res.exceptionOrNull() as Exception
            }

            helper.updateHashState(updatedConfig)
            return Round5(this, helper, updatedConfig) to null
        } catch (e: Exception) {
            return this to e
        }
    }

    override fun messageContent(): Content? {
        return Message4()
    }

    override fun number(): Number {
        return Number(4.toUShort())
    }

    fun schnorrCommitments() : MutableMap<ID, Commitment> {
        return previousRound.schnorrCommitments
    }

}

class Broadcast4 (
    val mod: perun_network.ecdsa_threshold.zk.mod.Proof? = null,
    val prm: perun_network.ecdsa_threshold.zk.prm.Proof? = null
) : NormalBroadcastContent() {
    override fun roundNumber(): Number {
        return Number(4.toUShort())
    }
}

class Message4(
    val share: CipherText? = null, // Encryption of the receiver's share
    val fac: perun_network.ecdsa_threshold.zk.fac.Proof? = null
) : Content {
    override fun roundNumber(): Number = Number(4.toUShort())
}