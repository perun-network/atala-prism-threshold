package sign

import mu.KotlinLogging
import org.kotlincrypto.hash.sha2.SHA256
import perun_network.ecdsa_threshold.ecdsa.PartialSignature
import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.keygen.*
import perun_network.ecdsa_threshold.paillier.PaillierCipherText
import perun_network.ecdsa_threshold.sign.Broadcast
import perun_network.ecdsa_threshold.sign.combinePartialSignatures
import perun_network.ecdsa_threshold.sign.presign.*
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertTrue

val logger = KotlinLogging.logger {}

class ThresholdSignTest {
    @Test
    fun testThresholdSign() {
        val n = 5 // Number of total parties.
        val t = 3 // Threshold of minimum required signers.

        // Generate Precomputations (Assuming the secret primes are precomputed).
        val (ids, secretPrecomps, publicPrecomps) = getSamplePrecomputations(n, t) // Use generatePrecomputation instead to generate new safe primes.
        logger.info {"Precomputation finished for $n signerIds with threshold $t"}

        // Message
        val message = "hello"
        val hash = SHA256().digest(message.toByteArray())

        // Determine signerIds
        val signerIds = randomSignerIDs(ids, t)
        logger.info {"signerIds: $signerIds"}
        val publicKey = publicKeyFromShares(signerIds, publicPrecomps)
        val (scaledPrecomps, scaledPublics, publicPoint) = scalePrecomputations(signerIds, secretPrecomps, publicPrecomps)
        if (publicKey != publicPoint.toPublicKey()) {
            throw IllegalStateException("Inconsistent public Key")
        }
        logger.info {"Scaled precomputations finished.\n"}

        // Prepare the signers
        val signers = mutableMapOf<Int, Presigner>()
        for (i in signerIds) {
            signers[i] = Presigner(
                id = i,
                private = scaledPrecomps[i]!!,
                publicPrecomps = scaledPublics
            )
        }
        
        // **PRESIGN**
        // PRESIGN ROUND 1
        val presignRound1AllBroadcasts = mutableMapOf<Int, Map<Int, PresignRound1Broadcast>>()
        val Ks = mutableMapOf<Int, PaillierCipherText>() // K_i of every party
        val elGamalPublics = mutableMapOf<Int, ElGamalPublic>()

        for (i in signerIds) {
            presignRound1AllBroadcasts[i] = signers[i]!!.presignRound1(signerIds)
            Ks[i] = signers[i]!!.K!!
            elGamalPublics[i] = signers[i]!!.elGamalPublic!!
        }
        logger.info {"Finish Presign Round 1"}

        // PRESIGN ROUND 2
        val bigGammaShares = mutableMapOf<Int, Point>()
        val presignRound2AllBroadcasts = mutableMapOf<Int, Map<Int, PresignRound2Broadcast>>()
        for (i in signerIds) {
            val presignRound1Broadcasts = filterIncomingBroadcast(i, presignRound1AllBroadcasts)
            presignRound2AllBroadcasts[i] = signers[i]!!.presignRound2(signerIds, Ks, presignRound1Broadcasts)

            bigGammaShares[i] = signers[i]!!.bigGammaShare!!
        }
        logger.info {"Finish Presign Round 2.\n"}

        // PRESIGN ROUND 3
        val presignRound3AllBroadcasts = mutableMapOf<Int, Map<Int, PresignRound3Broadcast>>()
        val deltaShares = mutableMapOf<Int,BigInteger>()
        val bigDeltaShares = mutableMapOf<Int,Point>()
        for (i in signerIds) {
            val presignRound2Broadcasts = filterIncomingBroadcast(i, presignRound2AllBroadcasts)
            presignRound3AllBroadcasts[i] = signers[i]!!.presignRound3(signerIds, bigGammaShares, elGamalPublics, presignRound2Broadcasts)
            deltaShares[i] = signers[i]!!.deltaShare!!
            bigDeltaShares[i] = signers[i]!!.bigDeltaShare!!
        }
        logger.info {"Finish Presign Round 3.\n"}

        // PROCESS PRESIGN OUTPUTS
        for (i in signerIds) {
            val presignRound3Broadcasts = filterIncomingBroadcast(i, presignRound3AllBroadcasts)
            signers[i]!!.processPresignOutput(signerIds, presignRound3Broadcasts, elGamalPublics, deltaShares, bigDeltaShares)
        }

        // ** PARTIAL SIGNING **
        val partialSignatures = mutableListOf<PartialSignature>()
        logger.info {"Partial signing the message: \"$message\""}

        for (i in signerIds) {
            partialSignatures.add(signers[i]!!.partialSignMessage(scaledPublics[i]!!.ssid, hash))
        }
        logger.info {"Finish ECDSA Partial Signing.\n"}

        // ** ECDSA SIGNING **
        val ecdsaSignature= combinePartialSignatures(signers[signerIds[0]]!!.bigR!!, partialSignatures, publicPoint, hash)

        assertTrue(ecdsaSignature.verifySecp256k1(hash, publicKey), "failed to convert and verified ecdsa signature")
    }

    private fun randomSignerIDs(ids: List<Int>, t: Int) : List<Int> {
        require(t <= ids.size) { "t must be less than or equal to the number of parties." }
        require(t > 0) { "t must be greater than 0." }

        return ids.shuffled().take(t)
    }

    private fun <A : Broadcast> filterIncomingBroadcast(id: Int, broadcasts: MutableMap<Int, Map<Int, A>>) : Map<Int, A> {
        val incomingBroadcasts = mutableMapOf<Int, A>()
        for ((j, broadcast) in broadcasts) {
            if (j != id) {
                incomingBroadcasts[j] = broadcast[id]!!
            }
        }
        return incomingBroadcasts
    }
}
