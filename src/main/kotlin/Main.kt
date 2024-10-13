package perun_network.ecdsa_threshold

import org.kotlincrypto.hash.sha2.SHA256
import perun_network.ecdsa_threshold.ecdsa.PartialSignature
import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.keygen.getSamplePrecomputations
import perun_network.ecdsa_threshold.keygen.publicKeyFromShares
import perun_network.ecdsa_threshold.keygen.scalePrecomputations
import perun_network.ecdsa_threshold.paillier.PaillierCipherText
import perun_network.ecdsa_threshold.presign.*
import perun_network.ecdsa_threshold.sign.SignParty
import perun_network.ecdsa_threshold.sign.combinePartialSignatures
import perun_network.ecdsa_threshold.sign.processPresignOutput
import perun_network.ecdsa_threshold.zero_knowledge.ZeroKnowledgeException
import java.math.BigInteger

/**
 * Main function to demonstrate the threshold ECDSA signing process.
 */
@OptIn(ExperimentalStdlibApi::class)
fun main() {
    val n = 5
    val t = 3

    val startTime = System.currentTimeMillis() // capture the start time

    // Generate Precomputations (Assuming the secret primes are precomputed).
    val (ids, secretPrecomps, publicPrecomps) = getSamplePrecomputations(n, t, n) // Use generatePrecomputation instead to generate new safe primes.
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
    println("Finish Presign Round 1")

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
                if (!presignRound2Inputs[i]!!.verifyPresignRound1Output(j, presign1output[i]!!)) {
                    throw ZeroKnowledgeException("failed to validate enc proof for K from $j to $i")
                }
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
    println("Finish Presign Round 2.\n")

    // PRESIGN ROUND 3
    val presignRound3Inputs = mutableMapOf<Int, PresignRound3Input>()
    val presignRound3Outputs = mutableMapOf<Int, Map<Int, PresignRound3Output>>()
    val deltaShares = mutableMapOf<Int,BigInteger>()
    val bigDeltaShares = mutableMapOf<Int,Point>()
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
                if (!presignRound3Inputs[i]!!.verifyPresignRound2Output(
                        j,
                        presign2output[i]!!,
                        KShares[i]!!,
                        GShares[j]!!,
                        scaledPublics[j]!!.publicEcdsa
                    )
                ) {
                    throw ZeroKnowledgeException("failed to validate presign round 2 output from $j to $i")
                }
                println("Validated presign round 2 output from $j to $i ")
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

    println("Finish Presign Round 3.\n")

    // ** PARTIAL SIGNING **

    // process Presign output
    val bigR = processPresignOutput(
        signers= signerIds,
        deltaShares = deltaShares,
        bigDeltaShares = bigDeltaShares,
        gamma= bigGammas[signerIds[0]]!!
    )

    val partialsignerIds = mutableMapOf<Int, SignParty>()
    val partialSignatures = mutableListOf<PartialSignature>()
    println("Partial signing the message: \"$message\"")
    for (i in signerIds) {
        partialsignerIds[i] = SignParty(
            ssid = scaledPrecomps[i]!!.ssid,
            id = scaledPrecomps[i]!!.id,
            publics = scaledPublics,
            hash = hash,
        )

        // Verify Presign outputs
        for (j in signerIds) {
            if (j != i) {
                if (!partialsignerIds[i]!!.verifyPresignRound3Output(j, presignRound3Outputs[j]!![i]!!, KShares[j]!!)) {
                    throw ZeroKnowledgeException("failed to validate presign round 3 output from $j to $i")
                }
                println("Validated presign round 3 output from $j to $i ")
            }
        }

        // Produce partial signature
        partialSignatures.add(partialsignerIds[i]!!.createPartialSignature(
            kShare = signers[i]!!.kShare!!,
            chiShare = signers[i]!!.chiShare!!,
            bigR= bigR
        ))
    }
    println("Finish ECDSA Partial Signing.\n")


    // ** ECDSA SIGNING **
    val ecdsaSignature= combinePartialSignatures(bigR, partialSignatures, publicPoint, hash)
    println("Finish Combining ECDSA Partial Signatures: ${ecdsaSignature.toSecp256k1Signature().toHexString().uppercase()}.\n")


    if (ecdsaSignature.verifySecp256k1(hash, publicKey)) {
        println("ECDSA signature convert successfully.\n")
    } else {
        println("failed to convert and verified ecdsa signature.\n")
    }

    val endTime = System.currentTimeMillis() // End time in milliseconds
    val elapsedTime = (endTime - startTime) / 1000.0 // Convert milliseconds to seconds

    println("Execution time: $elapsedTime seconds")
}

/**
 * Chooses a random list of t signerIds from the given list of ids.
 *
 * @param ids A list of signer IDs.
 * @param t The number of signerIds to randomly select.
 * @return A list containing t randomly selected signer IDs.
 */
fun randomSigners(ids: List<Int>, t : Int) : List<Int> {
    require(t <= ids.size) { "t must be less than or equal to n" }

    // Shuffle the list and take the first t elements
    return ids.shuffled().take(t)
}