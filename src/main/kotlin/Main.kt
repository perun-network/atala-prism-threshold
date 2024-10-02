package perun_network.ecdsa_threshold

import com.ionspin.kotlin.bignum.integer.Sign
import org.kotlincrypto.hash.sha2.SHA256
import perun_network.ecdsa_threshold.ecdsa.PartialSignature
import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.keygen.generatePrecomputations
import perun_network.ecdsa_threshold.keygen.publicKeyFromShares
import perun_network.ecdsa_threshold.keygen.scalePrecomputations
import perun_network.ecdsa_threshold.math.random
import perun_network.ecdsa_threshold.paillier.PaillierCipherText
import perun_network.ecdsa_threshold.presign.*
import perun_network.ecdsa_threshold.sign.SignParty
import perun_network.ecdsa_threshold.sign.partialSining
import perun_network.ecdsa_threshold.sign.processPresignOutput
import perun_network.ecdsa_threshold.zero_knowledge.ZeroKnowledgeException
import java.math.BigInteger
import java.util.Random

fun main() {
    val n = 3
    val t = 2

    // Generate Precomputations
    val (ids, precomps ) = generatePrecomputations(n, t)
    println("Precomputation finished for $n signers with threshold $t")

    // Message
    val message = "hello".toByteArray()
    val hash = SHA256().digest(message)

    // Determine signers
    val signers = randomSigners(ids, t)
    println("Signers: $signers")
    val publicKey = publicKeyFromShares(signers, precomps[ids[0]]!!.publics)
    val scaledPrecomps = scalePrecomputations(signers, precomps)
    println("Scaled precomputations finished")

    // **PRESIGN**
    // PRESIGN ROUND 1
    val presignRound1Inputs = mutableMapOf<Int, PresignRound1Input>()
    val presignRound1Outputs = mutableMapOf<Int, Map<Int, PresignRound1Output>>()
    val ks = mutableMapOf<Int, PaillierCipherText>() // K_i of every party
    val gs = mutableMapOf<Int, PaillierCipherText>() // G_i of every party
    val ecdsaPublics = mutableMapOf<Int, Point>() // ecdsa public share of every party


    val gammaShares = mutableMapOf<Int, Scalar>()
    val kShares = mutableMapOf<Int, Scalar>()
    val gNonces = mutableMapOf<Int, BigInteger>()
    val kNonces = mutableMapOf<Int, BigInteger>()
    for (i in signers) {
        presignRound1Inputs[i] = PresignRound1Input(
            ssid = scaledPrecomps[i]!!.ssid,
            id = scaledPrecomps[i]!!.id,
            publics = scaledPrecomps[i]!!.publics
        )

        // Produce Presign Round1 output
        val (output, gammaShare, kShare, gNonce, kNonce, K, G) = presignRound1Inputs[i]!!.producePresignRound1Output(signers)
        presignRound1Outputs[i] = output
        gammaShares[i] = gammaShare
        kShares[i] = kShare
        gNonces[i] = gNonce
        kNonces[i] = kNonce
        ks[i] = K
        gs[i] = G
        ecdsaPublics[i] = scaledPrecomps[i]!!.publics[i]!!.publicEcdsa
    }
    println("Finish Presign Round 1")

    // PRESIGN ROUND 2
    val bigGammaShares = mutableMapOf<Int, Point>()
    val presignRound2Inputs = mutableMapOf<Int, PresignRound2Input>()
    val presignRound2Outputs = mutableMapOf<Int, Map<Int, PresignRound2Output>>()
    for (i in signers) {
        // Prepare Presign Round 2 Inputs
        presignRound2Inputs[i] = PresignRound2Input(
            ssid = scaledPrecomps[i]!!.ssid,
            id = scaledPrecomps[i]!!.id,
            gammaShare = gammaShares[i]!!,
            secretECDSA = scaledPrecomps[i]!!.ecdsaShare,
            secretPaillier = scaledPrecomps[i]!!.paillierSecret ,
            gNonce = gNonces[i]!!,
            publics = scaledPrecomps[i]!!.publics
        )

        // Verify Presign Round 1 Outputs
        for ((j, presign1output)  in presignRound1Outputs) {
            if (j != i) {
                if (!presignRound2Inputs[i]!!.verifyPresignRound1Output(j, presign1output[i]!!)) {
                    throw ZeroKnowledgeException("failed to validate enc proof for K from $j to $i")
                }
            }
        }

        // Produce Presign Round2 output
        val (presign2output, bigGammaShare) = presignRound2Inputs[i]!!.producePresignRound2Output(
            signers,
            ks,
            gs,
            ecdsaPublics)

        presignRound2Outputs[i] = presign2output
        bigGammaShares[i] = bigGammaShare
    }
    println("Finish Presign Round 2")

    // PRESIGN ROUND 3
    val presignRound3Inputs = mutableMapOf<Int, PresignRound3Input>()
    val presignRound3Outputs = mutableMapOf<Int, Map<Int, PresignRound3Output>>()
    val deltaShares = mutableMapOf<Int,BigInteger>()
    val bigDeltaShares = mutableMapOf<Int,Point>()
    val chiShares = mutableMapOf<Int, BigInteger>()
    val bigGammas = mutableMapOf<Int, Point>()
    for (i in signers) {
        // Prepare Presign Round 3 Inputs
        presignRound3Inputs[i] = PresignRound3Input(
            ssid = scaledPrecomps[i]!!.ssid,
            id = scaledPrecomps[i]!!.id,
            gammaShare = gammaShares[i]!!.value,
            secretPaillier = scaledPrecomps[i]!!.paillierSecret,
            kShare = kShares[i]!!,
            kI = ks[i]!!,
            kNonce = kNonces[i]!!,
            secretECDSA = scaledPrecomps[i]!!.ecdsaShare.value,
            publics = scaledPrecomps[i]!!.publics
        )

        // Verify Presign Round 2 Outputs
        for ((j, presign2output)  in presignRound2Outputs) {
            if (j != i) {
                if (!presignRound3Inputs[i]!!.verifyPresignRound2Output(
                        j,
                        presign2output[i]!!,
                        ks[i]!!,
                        gs[j]!!,
                        ecdsaPublics[j]!!
                    )
                ) {
                    throw ZeroKnowledgeException("failed to validate presign round 2 output from $j to $i")
                }
            }
        }

        // Produce Presign Round 3 output
        val (presign3output, chiShare, deltaShare, bigDeltaShare, bigGamma) = presignRound3Inputs[i]!!.producePresignRound3Output(
            signers,
            bigGammaShares[i]!!,
            presignRound2Outputs[i]!!)

        presignRound3Outputs[i] = presign3output
        chiShares[i] = chiShare
        deltaShares[i] = deltaShare
        bigDeltaShares[i] = bigDeltaShare
        bigGammas[i] = bigGamma
    }

    System.out.println("Finish Presign Round 3")

    // ** PARTIAL SIGNING **

    // process Presign output
    val bigR = processPresignOutput(
        signers= signers,
        deltaShares = deltaShares,
        bigDeltaShares = bigDeltaShares,
        gamma= bigGammas[signers[0]]!!
    )


    val partialSigners = mutableMapOf<Int, SignParty>()
    val partialSignatures = mutableListOf<PartialSignature>()

    for (i in signers) {
        partialSigners[i] = SignParty(
            ssid = scaledPrecomps[i]!!.ssid,
            id = scaledPrecomps[i]!!.id,
            publics = scaledPrecomps[i]!!.publics,
            hash = hash,
        )

        // Verify Presign outputs
        for (j in signers) {
            if (j != i) {
                if (partialSigners[i]!!.verifyPresignRound3Output(j, presignRound3Outputs[j]!![i]!!, ks[j]!!)) {
                    throw ZeroKnowledgeException("failed to validate presign round 3 output from $j to $i")
                }
            }
        }

        // Produce partial signature
        partialSignatures.add(partialSigners[i]!!.createPartialSignature(
            kShare = kShares[i]!!,
            chiShare = gammaShares[i]!!,
            bigR= bigR
        ))
    }
    System.out.println("Finish ECDSA Partial Signing")

    // ** ECDSA SIGNING **
    val ecdsaSignature = partialSining(bigR, partialSignatures)
    System.out.println("Finish ECDSA Signing")

    // Verify ECDSA Signature
    if (ecdsaSignature.verify(hash, publicKey)) {
        System.out.println("ECDSA signature verified")
    } else {
        System.out.println("ECDSA signature not verified")
    }
}

fun randomSigners(ids: List<Int>, t : Int) : List<Int> {
    require(t <= ids.size) { "t must be less than or equal to n" }

    // Shuffle the list and take the first t elements
    return ids.shuffled().take(t)
}