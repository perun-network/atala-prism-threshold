package sign

import org.junit.jupiter.api.assertDoesNotThrow
import org.kotlincrypto.hash.sha2.SHA256
import perun_network.ecdsa_threshold.ecdsa.PartialSignature
import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.keygen.*
import perun_network.ecdsa_threshold.paillier.PaillierCipherText
import perun_network.ecdsa_threshold.randomSigners
import perun_network.ecdsa_threshold.sign.ThresholdSigner
import perun_network.ecdsa_threshold.sign.combinePartialSignatures
import perun_network.ecdsa_threshold.sign.presign.*
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue




class ThresholdSignTest {
    @Test
    fun testThresholdSign() {
        val n = 5 // Number of total parties.
        val t = 3 // Threshold of minimum required signers.

        val startTime = System.currentTimeMillis() // capture the start time

        // Generate Precomputations (Assuming the secret primes are precomputed).
        val (ids, secretPrecomps, publicPrecomps) = getSamplePrecomputations(n, t) // Use generatePrecomputation instead to generate new safe primes.
        println("Precomputation finished for $n signerIds with threshold $t")

        // Message
        val message = "hello"
        val hash = SHA256().digest(message.toByteArray())

        // Determine signerIds
        val signerIds = randomSigners(ids, t)
        println("signerIds: $signerIds")
        val publicKey = publicKeyFromShares(signerIds, publicPrecomps)
        val (scaledPrecomps, scaledPublics, publicPoint) = scalePrecomputations(signerIds, secretPrecomps, publicPrecomps)
        if (publicKey != publicPoint.toPublicKey()) {
            throw IllegalStateException("Inconsistent public Key")
        }
        println("Scaled precomputations finished.\n")

        // Prepare the signers
        val signers = mutableMapOf<Int, ThresholdSigner>()
        for (i in signerIds) {
            signers[i] = ThresholdSigner(
                id = i,
                private = scaledPrecomps[i]!!,
                publicPrecomps = scaledPublics
            )
        }
        
        // **PRESIGN**
        // PRESIGN ROUND 1
        val presignRound1Broadcasts = mutableMapOf<Int, Map<Int, PresignRound1Broadcast>>()
        val Ks = mutableMapOf<Int, PaillierCipherText>() // K_i of every party
        val elGamalPublics = mutableMapOf<Int, ElGamalPublic>()


        for (i in signerIds) {
            presignRound1Broadcasts[i] = signers[i]!!.presignRound1(signerIds)
            Ks[i] = signers[i]!!.K!!
            elGamalPublics[i] = signers[i]!!.elGamalPublic!!
        }
        println("Finish Presign Round 1")

        // PRESIGN ROUND 2
        val bigGammaShares = mutableMapOf<Int, Point>()
        val presignRound2Broadcasts = mutableMapOf<Int, Map<Int, PresignRound2Broadcast>>()
        for (i in signerIds) {
            presignRound2Broadcasts[i] = signers[i]!!.presignRound2(signerIds, Ks, presignRound1Broadcasts)

            bigGammaShares[i] = signers[i]!!.bigGammaShare!!
        }
        println("Finish Presign Round 2.\n")

        // PRESIGN ROUND 3
        val presignRound3Broadcasts = mutableMapOf<Int, Map<Int, PresignRound3Broadcast>>()
        val deltaShares = mutableMapOf<Int,BigInteger>()
        val bigDeltaShares = mutableMapOf<Int,Point>()
        for (i in signerIds) {
            presignRound3Broadcasts[i] = signers[i]!!.presignRound3(signerIds, bigGammaShares, elGamalPublics, presignRound2Broadcasts)
            deltaShares[i] = signers[i]!!.deltaShare!!
            bigDeltaShares[i] = signers[i]!!.bigDeltaShare!!
        }
        println("Finish Presign Round 3.\n")

        // PROCESS PRESIGN OUTPUTS
        for (i in signerIds) {
            signers[i]!!.processPresignOutput(signerIds, presignRound3Broadcasts, elGamalPublics, deltaShares, bigDeltaShares)
        }

        // ** PARTIAL SIGNING **
        val partialSignatures = mutableListOf<PartialSignature>()
        println("Partial signing the message: \"$message\"")

        for (i in signerIds) {
            partialSignatures.add(signers[i]!!.partialSignMessage(scaledPublics[i]!!.ssid, hash))
        }
        println("Finish ECDSA Partial Signing.\n")


        // ** ECDSA SIGNING **
        val ecdsaSignature= combinePartialSignatures(signers[signerIds[0]]!!.bigR!!, partialSignatures, publicPoint, hash)

        assertTrue(ecdsaSignature.verifySecp256k1(hash, publicKey), "failed to convert and verified ecdsa signature")
    }

}