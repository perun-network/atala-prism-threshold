package perun_network.ecdsa_threshold.protocols.cmp.presign

import kotlinx.coroutines.channels.Channel
import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.internal.round.*
import perun_network.ecdsa_threshold.internal.round.RoundErrors.ErrInvalidContent
import perun_network.ecdsa_threshold.math.curve.Scalar
import perun_network.ecdsa_threshold.party.ID
import perun_network.ecdsa_threshold.zk.nth.Proof
import java.math.BigInteger
import perun_network.ecdsa_threshold.internal.round.Number
import perun_network.ecdsa_threshold.protocols.cmp.paillier.CipherText
import perun_network.ecdsa_threshold.protocols.cmp.paillier.PublicKey
import perun_network.ecdsa_threshold.protocols.cmp.paillier.SecretKey
import perun_network.ecdsa_threshold.zk.nth.Private
import perun_network.ecdsa_threshold.zk.nth.Public

class Abort1(
    private val presign6: Presign6,
    private val helper: Helper,
    val gammaShares: MutableMap<ID, BigInteger>,
    val kShares: MutableMap<ID, BigInteger>,
    val deltaAlphas: MutableMap<ID, MutableMap<ID, BigInteger>>
) : Session, BroadcastRound {

    override fun group() = presign6.group()
    override suspend fun hash() = presign6.hash()
    override fun protocolID() = presign6.protocolID()
    override fun finalRoundNumber() = presign6.finalRoundNumber()
    override fun ssid() = presign6.ssid()
    override fun selfID() = presign6.selfID()
    override fun partyIDs() = presign6.partyIDs()
    override fun otherPartyIDs() = presign6.otherPartyIDs()
    override fun threshold() = presign6.threshold()
    override fun n() = presign6.n()

    override suspend fun storeBroadcastMessage(msg: Message): Exception? {
        val body = msg.content as? BroadcastAbort1 ?: return ErrInvalidContent

        val alphas = mutableMapOf<ID, BigInteger>()
        for ((id, deltaProof) in body.deltaProofs) {
            alphas[id] = deltaProof.plaintext
        }
        deltaAlphas[msg.from] = alphas
        gammaShares[msg.from] = body.gammaShare!!
        kShares[msg.from] = body.kProof!!.plaintext

        val public = presign6.paillier()[msg.from]
        if (!body.kProof.verify(helper.hashForID(msg.from), public!!, presign6.k()[msg.from]!!)) {
            return Exception("Failed to verify validity of k")
        }

        val bigGammaShareActual = group().newScalar().setNat(body.gammaShare.mod(group().order())).actOnBase()
        if (!presign6.bigGammaShare()[msg.from]!!.equals(bigGammaShareActual)) {
            return Exception("Different BigGammaShare")
        }

        for ((id, deltaProof) in body.deltaProofs) {
            if (!deltaProof.verify(helper.hashForID(msg.from), public!!, presign6.deltaCiphertext()[msg.from]!![id]!!)) {
                return Exception("Failed to validate Delta MtA Nth proof")
            }
        }
        return null
    }

    override suspend fun verifyMessage(msg: Message): Exception? {
        return null
    }

    override fun storeMessage(msg: Message): Exception? {
        return null
    }

    override suspend fun finalize(out: Channel<Message>): Pair<Session?, Exception?> {
        val culprits = mutableListOf<ID>()
        var delta : BigInteger
        var tmp : BigInteger

        for (j in otherPartyIDs()) {
            delta = kShares[j]!!.multiply( gammaShares[j])
            for (l in partyIDs()) {
                if (l == j) continue

                delta = delta.add(deltaAlphas[j]!![l])
                tmp = kShares[l]!!.multiply(gammaShares[j])
                delta = delta.add(tmp)
                tmp =  deltaAlphas[l]!![j]!!.negate()
                delta = delta.add(tmp)
            }

            val deltaScalar = group().newScalar().setNat(delta.mod(group().order()))
            if (!deltaScalar.equals(presign6.deltaShares()[j])) {
                culprits.add(j)
            }
        }

        return helper.abortRound(Exception("abort1: detected culprit"), *culprits.toTypedArray()) to null
    }

    override fun messageContent(): Content? {
        return null
    }

    override fun broadcastContent(): BroadcastContent {
        return BroadcastAbort1(null, null, mutableMapOf())
    }

    override fun number(): Number {
        return Number(7u)
    }
}

data class BroadcastAbort1(
    val gammaShare: BigInteger?,
    val kProof: AbortNth?,
    val deltaProofs: MutableMap<ID, AbortNth>
) : NormalBroadcastContent() {
    override fun roundNumber(): Number = Number(7u)
}

class AbortNth(
    val plaintext: BigInteger,
    val nonce: BigInteger,
    val proof: Proof
) {

    companion object {
        fun proveNth(hash: Hash, paillierSecret: SecretKey, ciphertext: CipherText): AbortNth {
            val nSquared = paillierSecret.publicKey.modulusSquared()
            val n = paillierSecret.publicKey.modulus()
            val (plaintext, nonce) = paillierSecret.decryptWithRandomness(ciphertext)
            val nonceHidden = nonce.modPow(n, nSquared)
            val proof = Proof.newProof(hash, Public(paillierSecret.publicKey, nonceHidden), Private(nonce))

            return AbortNth(
                plaintext = plaintext,
                nonce = nonceHidden,
                proof = proof
            )
        }
    }

    fun verify(hash: Hash, paillierPublic: PublicKey, ciphertext: CipherText): Boolean {
        val one = BigInteger.ONE

        val cExpected = ciphertext.value()
        val cActual = paillierPublic.encWithNonce(plaintext, one).value().multiply(nonce).mod(paillierPublic.modulusSquared())

        if (!cExpected.equals(cActual)) {
            return false
        }

        return proof.verify(hash, Public(paillierPublic, nonce))
    }
}