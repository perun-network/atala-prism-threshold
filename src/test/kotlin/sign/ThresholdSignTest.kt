package sign

import org.kotlincrypto.hash.sha2.SHA256
import perun_network.ecdsa_threshold.ecdsa.PartialSignature
import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.keygen.*
import perun_network.ecdsa_threshold.paillier.PaillierCipherText
import perun_network.ecdsa_threshold.presign.*
import perun_network.ecdsa_threshold.randomSigners
import perun_network.ecdsa_threshold.sign.SignParty
import perun_network.ecdsa_threshold.presign.ThresholdSigner
import perun_network.ecdsa_threshold.sign.combinePartialSignatures
import perun_network.ecdsa_threshold.sign.processPresignOutput
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue




class ThresholdSignTest {
    @Test
    fun testThresholdSign() {
        val n = 7
        val t = 5

        // Generate Precomputations (Assuming the secret primes are precomputed).
        val (ids, secretPrecomps, publicPrecomps) = getSamplePrecomputations(n, t, n) // Use generatePrecomputation instead to generate new safe primes.

        // Message
        val message = "Happy birthday to you!"
        val hash = SHA256().digest(message.toByteArray())

        // Determine signerIds
        val signerIds = randomSigners(ids, t)
        val publicKey = publicKeyFromShares(signerIds, publicPrecomps)
        val (scaledPrecomps, scaledPublics, publicPoint) = scalePrecomputations(signerIds, secretPrecomps, publicPrecomps)
        assertEquals(publicPoint.toPublicKey(), publicKey, "inconsistent public key")

        // Prepare the signers
        val signers = mutableMapOf<Int, ThresholdSigner>()
        for (i in signerIds) {
            signers[i] = ThresholdSigner(
                id = i,
                private = scaledPrecomps[i]!!,
                publics = scaledPublics
            )
        }

        // **PRESIGN**
        // PRESIGN ROUND 1
        val presignRound1Inputs = mutableMapOf<Int, PresignRound1Input>()
        val presignRound1Outputs = mutableMapOf<Int, Map<Int, PresignRound1Output>>()
        val KShares = mutableMapOf<Int, PaillierCipherText>() // K_i of every party
        val GShares = mutableMapOf<Int, PaillierCipherText>() // G_i of every party


        for (i in signerIds) {
            presignRound1Inputs[i] = PresignRound1Input(
                ssid = scaledPrecomps[i]!!.ssid,
                id = scaledPrecomps[i]!!.id,
                publics = scaledPublics
            )

            // Produce Presign Round1 output
            val (output, gammaShare, kShare, gNonce, kNonce, K, G) = presignRound1Inputs[i]!!.producePresignRound1Output(signerIds)
            presignRound1Outputs[i] = output
            signers[i]!!.gammaShare = gammaShare
            signers[i]!!.kShare = kShare
            signers[i]!!.gNonce = gNonce
            signers[i]!!.kNonce = kNonce
            KShares[i] = K
            GShares[i] = G
        }

        // PRESIGN ROUND 2
        val bigGammaShares = mutableMapOf<Int, Point>()
        val presignRound2Inputs = mutableMapOf<Int, PresignRound2Input>()
        val presignRound2Outputs = mutableMapOf<Int, Map<Int, PresignRound2Output>>()
        for (i in signerIds) {
            // Prepare Presign Round 2 Inputs
            presignRound2Inputs[i] = PresignRound2Input(
                ssid = scaledPrecomps[i]!!.ssid,
                id = scaledPrecomps[i]!!.id,
                gammaShare = signers[i]!!.gammaShare!!,
                secretECDSA = scaledPrecomps[i]!!.ecdsaShare,
                secretPaillier = scaledPrecomps[i]!!.paillierSecret ,
                gNonce = signers[i]!!.gNonce!!,
                publics = scaledPublics
            )

            // Verify Presign Round 1 Outputs
            for ((j, presign1output)  in presignRound1Outputs) {
                if (j != i) {
                    assertTrue(presignRound2Inputs[i]!!.verifyPresignRound1Output(j, presign1output[i]!!), "failed to validate enc proof for K from $j to $i")
                    println("Validated presign round 1 output from $j to $i ")
                }
            }

            // Produce Presign Round2 output
            val (presign2output, bigGammaShare) = presignRound2Inputs[i]!!.producePresignRound2Output(
                signerIds,
                KShares,
                GShares)

            presignRound2Outputs[i] = presign2output
            bigGammaShares[i] = bigGammaShare
        }

        // PRESIGN ROUND 3
        val presignRound3Inputs = mutableMapOf<Int, PresignRound3Input>()
        val presignRound3Outputs = mutableMapOf<Int, Map<Int, PresignRound3Output>>()
        val deltaShares = mutableMapOf<Int, BigInteger>()
        val bigDeltaShares = mutableMapOf<Int, Point>()
        val bigGammas = mutableMapOf<Int, Point>()
        for (i in signerIds) {
            // Prepare Presign Round 3 Inputs
            presignRound3Inputs[i] = PresignRound3Input(
                ssid = scaledPrecomps[i]!!.ssid,
                id = scaledPrecomps[i]!!.id,
                gammaShare = signers[i]!!.gammaShare!!.value,
                secretPaillier = scaledPrecomps[i]!!.paillierSecret,
                kShare = signers[i]!!.kShare!!,
                K = KShares[i]!!,
                kNonce = signers[i]!!.kNonce!!,
                secretECDSA = scaledPrecomps[i]!!.ecdsaShare.value,
                publics = scaledPublics
            )

            // Verify Presign Round 2 Outputs
            for ((j, presign2output) in presignRound2Outputs) {
                if (j != i) {
                    assertTrue(presignRound3Inputs[i]!!.verifyPresignRound2Output(
                        j,
                        presign2output[i]!!,
                        KShares[i]!!,
                        GShares[j]!!,
                        scaledPublics[j]!!.publicEcdsa
                    ), "failed to validate presign round 2 output from $j to $i")
                }
            }

            // Produce Presign Round 3 output
            val (presign3output, chiShare, deltaShare, bigDeltaShare, bigGamma) = presignRound3Inputs[i]!!.producePresignRound3Output(
                signerIds,
                bigGammaShares,
                presignRound2Outputs)

            presignRound3Outputs[i] = presign3output
            signers[i]!!.chiShare = Scalar(chiShare)
            deltaShares[i] = deltaShare
            bigDeltaShares[i] = bigDeltaShare
            bigGammas[i] = bigGamma
        }

        // ** PARTIAL SIGNING **

        // process Presign output
        val bigR = processPresignOutput(
            signers= signerIds,
            deltaShares = deltaShares,
            bigDeltaShares = bigDeltaShares,
            gamma= bigGammas[signerIds[0]]!!
        )

        val partialSigners = mutableMapOf<Int, SignParty>()
        val partialSignatures = mutableListOf<PartialSignature>()
        for (i in signerIds) {
            partialSigners[i] = SignParty(
                ssid = scaledPrecomps[i]!!.ssid,
                id = scaledPrecomps[i]!!.id,
                publics = scaledPublics,
                hash = hash,
            )

            // Verify Presign outputs
            for (j in signerIds) {
                if (j != i) {
                    assertTrue(partialSigners[i]!!.verifyPresignRound3Output(j, presignRound3Outputs[j]!![i]!!, KShares[j]!!), "failed to validate presign round 3 output from $j to $i")
                    println("Validated presign round 3 output from $j to $i ")
                }
            }

            // Produce partial signature
            partialSignatures.add(partialSigners[i]!!.createPartialSignature(
                kShare = signers[i]!!.kShare!!,
                chiShare = signers[i]!!.chiShare!!,
                bigR= bigR
            ))
        }


        // ** ECDSA SIGNING **
        val ecdsaSignature= combinePartialSignatures(bigR, partialSignatures, publicPoint, hash)

        assertTrue(ecdsaSignature.verifySecp256k1(hash, publicKey), "failed to convert and verified ecdsa signature")
    }

}