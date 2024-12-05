package perun_network.ecdsa_threshold

import mu.KotlinLogging
import org.kotlincrypto.hash.sha2.SHA256
import perun_network.ecdsa_threshold.ecdsa.PartialSignature
import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.precomp.PublicPrecomputation
import perun_network.ecdsa_threshold.precomp.generateSessionId
import perun_network.ecdsa_threshold.precomp.publicKeyFromShares
import perun_network.ecdsa_threshold.sign.Signer
import perun_network.ecdsa_threshold.sign.aux.AuxRound1Broadcast
import perun_network.ecdsa_threshold.sign.aux.AuxRound2Broadcast
import perun_network.ecdsa_threshold.sign.aux.AuxRound3Broadcast
import perun_network.ecdsa_threshold.sign.combinePartialSignatures
import perun_network.ecdsa_threshold.sign.keygen.KeygenRound1Broadcast
import perun_network.ecdsa_threshold.sign.keygen.KeygenRound2Broadcast
import perun_network.ecdsa_threshold.sign.keygen.KeygenRound3Broadcast
import perun_network.ecdsa_threshold.sign.presign.PresignRound1Broadcast
import perun_network.ecdsa_threshold.sign.presign.PresignRound2Broadcast
import perun_network.ecdsa_threshold.sign.presign.PresignRound3Broadcast

private val logger = KotlinLogging.logger {}

/**
 * Main function to demonstrate the threshold ECDSA signing process.
 */
@OptIn(ExperimentalStdlibApi::class)
fun main() {
    val n = 5 // Number of total parties.
    val t = 3 // Threshold of minimum required signers.

    val startTime = System.currentTimeMillis() // capture the start time

    val ssid = generateSessionId()
    val parties = mutableMapOf<Int, Signer>()
    for (i in 1..n) {
        parties[i] = Signer(
            id = i,
            ssid = ssid,
            threshold = t,
        )
    }
    // KEY GENERATION
    logger.info {"Key generation started for $n signers with threshold $t \n" }
    keygen(parties)
    logger.info {"Key generation finished for $n signers with threshold $t \n" }

    // AUXILIARX INFO
    logger.info {"Begin auxiliary info protocol for parties: ${parties.keys} \n" }
    val publicPrecomps = aux(parties)
    logger.info {"Finished auxiliary info protocol for parties: ${parties.keys} \n" }

    // Determine signerIds
    val signers = randomSigners(parties, t)
    val signerIds = signers.keys.toList()
    logger.info {"Randomly chosen signers: $signerIds" }
    val publicKey = publicKeyFromShares(signers.keys.toList(), publicPrecomps)

    // Scale Secret/Public Precomputations
    val (publicPoint, _) =  scalePrecomputation(signers)
    if (publicKey != publicPoint.toPublicKey()) {
        throw IllegalStateException("Inconsistent public Key")
    }
    logger.info {"Scaled precomputations finished.\n" }

    // **PRESIGN**
    logger.info {"Begin Presigning protocol for signers $signerIds.\n" }
    val bigR = presign(signers)
    logger.info {"Finished presigning protocol for signers $signerIds.\n" }

    // Message
    val message = "hello"
    val hash = SHA256().digest(message.toByteArray())

    // ** PARTIAL SIGNING **
    logger.info {"Partial signing the message: \"$message\"" }
    val partialSignatures = partialSignMessage(signers, hash)
    logger.info {"Finish ECDSA Partial Signing.\n" }


    // ** ECDSA SIGNING **
    val ecdsaSignature= combinePartialSignatures(bigR, partialSignatures, publicPoint, hash)
    logger.info {"Finish Combining ECDSA Signature: ${ecdsaSignature.toSecp256k1Signature().toHexString().uppercase()}.\n" }

    // ** ECDSA VERIFICATION ** //

    if (ecdsaSignature.verifySecp256k1(hash, publicKey)) {
        logger.info {"ECDSA signature verified successfully.\n" }
    } else {
        logger.info {"failed to verify ecdsa signature.\n" }
    }

    val endTime = System.currentTimeMillis() // End time in milliseconds
    val elapsedTime = (endTime - startTime) / 1000.0 // Convert milliseconds to seconds

    logger.info {"Execution time: $elapsedTime seconds" }
}

/**
 * Chooses a random subset of t signerIds and their corresponding ThresholdSigners from the given map of parties.
 *
 * @param parties A map where the keys are signer IDs and the values are ThresholdSigners.
 * @param t The number of signerIds to randomly select.
 * @return A map containing t randomly selected signer IDs and their corresponding ThresholdSigners.
 */
fun randomSigners(parties: Map<Int, Signer>, t: Int): Map<Int, Signer> {
    require(t <= parties.size) { "t must be less than or equal to the number of parties." }
    require(t > 0) { "t must be greater than 0." }

    val partyIds = parties.keys.toList()

    // Shuffle the list and take the first t elements
    val signerIds = partyIds.shuffled().take(t)

    // Filter the map to include only the randomly selected signer IDs
    return parties.filterKeys { it in signerIds }
}

private fun scalePrecomputation(signers : Map<Int, Signer>) : Pair<Point, Map<Int, PublicPrecomputation>> {
    val publicPoints = mutableMapOf<Int, Point>()
    val publicAllPrecomps = mutableMapOf<Int, Map<Int, PublicPrecomputation>>()
    for (i in signers.keys.toList()) {
        val (publicPrecomp, publicPoint) = signers[i]!!.scalePrecomputations(signers.keys.toList())
        publicPoints[i] = publicPoint
        publicAllPrecomps[i] = publicPrecomp
    }

    // Check output consistency
    val referencePoint = publicPoints[signers.keys.first()]!!
    val referencePrecomp = publicAllPrecomps[signers.keys.first()]!!
    for (i in signers.keys) {
        if (publicPoints[i] != referencePoint) throw IllegalStateException("Inconsistent public Key")
    }

    return referencePoint to referencePrecomp
}


private fun keygen(parties : Map<Int, Signer>) {
    val startTime = System.currentTimeMillis() // capture the start time
    val partyIds = parties.keys.toList()
    // KEYGEN ROUND 1
    logger.info {"KEYGEN ROUND 1 started." }
    val keygenRound1AllBroadcasts = mutableMapOf<Int, Map<Int, KeygenRound1Broadcast>>()
    for (i in partyIds) {
        keygenRound1AllBroadcasts[i] = parties[i]!!.keygenRound1(partyIds)
    }
    logger.info {"KEYGEN ROUND 1 finished.\n" }

    // KEYGEN ROUND 2
    logger.info {"KEYGEN ROUND 2 started." }
    val keygenRound2AllBroadcasts = mutableMapOf<Int, Map<Int, KeygenRound2Broadcast>>()
    for (i in partyIds) {
        keygenRound2AllBroadcasts[i] = parties[i]!!.keygenRound2(partyIds)
    }
    logger.info {"KEYGEN ROUND 2 finished.\n" }

    // KEYGEN ROUND 3
    logger.info {"KEYGEN ROUND 3 started." }
    val keygenRound3AllBroadcasts = mutableMapOf<Int, Map<Int, KeygenRound3Broadcast>>()
    for (i in partyIds) {
        keygenRound3AllBroadcasts[i] = parties[i]!!.keygenRound3(partyIds, keygenRound1AllBroadcasts, keygenRound2AllBroadcasts)
    }
    logger.info {"KEYGEN ROUND 3 finished.\n" }

    // KEYGEN OUTPUT
    logger.info {"PROCESS KEYGEN OUTPUT." }
    val publicPoints = mutableMapOf<Int, Point>()
    for (i in partyIds) {
        publicPoints[i] = parties[i]!!.keygenOutput(partyIds, keygenRound2AllBroadcasts, keygenRound3AllBroadcasts)
    }

    val endTime = System.currentTimeMillis() // End time in milliseconds
    val elapsedTime = (endTime - startTime) / 1000.0 // Convert milliseconds to seconds
    logger.info {"KEYGEN FINISHED after $elapsedTime seconds.\n" }


    // Check all public Points
    val publicPoint = publicPoints[partyIds[0]]!!
    for (i in partyIds) {
        if (publicPoints[i] != publicPoint) throw IllegalStateException("Inconsistent public Key")
    }
}

private fun aux(parties: Map<Int, Signer>) : Map<Int, PublicPrecomputation> {
    val startTime = System.currentTimeMillis() // capture the start time
    val partyIds = parties.keys.toList()

    // AUX ROUND 1
    logger.info {"AUX ROUND 1 started." }
    val auxRound1AllBroadcasts = mutableMapOf<Int, Map<Int, AuxRound1Broadcast>>()
    for (i in partyIds) {
        auxRound1AllBroadcasts[i] = parties[i]!!.auxRound1(partyIds)
    }
    logger.info {"AUX ROUND 1 finished.\n" }

    // AUX ROUND 2
    logger.info {"AUX ROUND 2 started." }
    val auxRound2AllBroadcasts = mutableMapOf<Int, Map<Int, AuxRound2Broadcast>>()
    for (i in partyIds) {
        auxRound2AllBroadcasts[i] = parties[i]!!.auxRound2(partyIds)
    }
    logger.info {"AUX ROUND 2 finished.\n" }

    // AUX ROUND 3
    logger.info {"AUX ROUND 3 started." }
    val auxRound3AllBroadcasts = mutableMapOf<Int, Map<Int, AuxRound3Broadcast>>()
    for (i in partyIds) {
        auxRound3AllBroadcasts[i] = parties[i]!!.auxRound3(partyIds, auxRound1AllBroadcasts, auxRound2AllBroadcasts)
    }
    logger.info {"AUX ROUND 3 finished.\n" }

    // AUX OUTPUT
    logger.info {"PROCESS AUX OUTPUT." }
    val publicPrecomps = mutableMapOf<Int, Map<Int, PublicPrecomputation>>()
    for (i in partyIds) {
        publicPrecomps[i] = parties[i]!!.auxOutput(partyIds, auxRound2AllBroadcasts, auxRound3AllBroadcasts)
    }

    val endTime = System.currentTimeMillis() // End time in milliseconds
    val elapsedTime = (endTime - startTime) / 1000.0 // Convert milliseconds to seconds
    logger.info {"AUX FINISHED after $elapsedTime seconds.\n" }

    // Check all public Points
    val publicPrecomp = publicPrecomps[partyIds[0]]!!
    for (i in partyIds) {
        for (j in partyIds) {
            if (publicPrecomps[i]!![j]!! != publicPrecomp[j]) {
                throw IllegalStateException("Inconsistent public precomputations of index $j from party $i.")
            }
        }
    }

    return publicPrecomp
}



private fun presign(signers: Map<Int, Signer>) : Point {
    val startTime = System.currentTimeMillis() // capture the start time
    val signerIds = signers.keys.toList()

    // PRESIGN ROUND 1
    logger.info {"PRESIGN ROUND1 started." }
    val presignRound1AllBroadcasts = mutableMapOf<Int, Map<Int, PresignRound1Broadcast>>()
    for (i in signerIds) {
        presignRound1AllBroadcasts[i] = signers[i]!!.presignRound1(signerIds)
    }
    logger.info {"PRESIGN ROUND 1 finished.\n" }

    // PRESIGN ROUND 2
    logger.info {"PRESIGN ROUND 2 started." }
    val presignRound2AllBroadcasts = mutableMapOf<Int, Map<Int, PresignRound2Broadcast>>()
    for (i in signerIds) {
        presignRound2AllBroadcasts[i] = signers[i]!!.presignRound2(signerIds, presignRound1AllBroadcasts)
    }
    logger.info {"PRESIGN ROUND 2 finished.\n" }

    // PRESIGN ROUND 3
    logger.info {"PRESIGN ROUND 3 started." }
    val presignRound3AllBroadcasts = mutableMapOf<Int, Map<Int, PresignRound3Broadcast>>()
    for (i in signerIds) {
        presignRound3AllBroadcasts[i] = signers[i]!!.presignRound3(signerIds, presignRound2AllBroadcasts)
    }
    logger.info {"PRESIGN ROUND 3 finished.\n" }

    // PRESIGN OUTPUT
    logger.info {"Process PRESIGN output." }
    val bigRs = mutableMapOf<Int, Point>()
    for (i in signerIds) {
        bigRs[i] = signers[i]!!.presignOutput(signerIds, presignRound3AllBroadcasts)
    }

    // VERIFY OUTPUT CONSISTENCY
    val referenceBigR = bigRs[signerIds[0]]!!
    for (i in signerIds) {
        if (referenceBigR != bigRs[i]) throw IllegalStateException("Inconsistent public Key")
    }
    val endTime = System.currentTimeMillis() // End time in milliseconds
    val elapsedTime = (endTime - startTime) / 1000.0 // Convert milliseconds to seconds
    logger.info {"PRESIGN finished after $elapsedTime seconds.\n" }
    return referenceBigR
}

private fun partialSignMessage(signers: Map<Int, Signer>, hash: ByteArray) : List<PartialSignature> {
    val partialSignatures = mutableListOf<PartialSignature>()

    for (i in signers.keys.toList()) {
        partialSignatures.add(signers[i]!!.partialSignMessage(hash))
    }

    return partialSignatures
}



