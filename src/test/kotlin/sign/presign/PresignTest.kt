package sign.presign

import org.kotlincrypto.hash.sha2.SHA256
import perun_network.ecdsa_threshold.ecdsa.PartialSignature
import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.math.sampleScalar
import perun_network.ecdsa_threshold.paillier.PaillierCipherText
import perun_network.ecdsa_threshold.precomp.generateSessionId
import perun_network.ecdsa_threshold.precomp.getSamplePrecomputations
import perun_network.ecdsa_threshold.precomp.publicKeyFromShares
import perun_network.ecdsa_threshold.precomp.scalePrecomputations
import perun_network.ecdsa_threshold.sign.Broadcast
import perun_network.ecdsa_threshold.sign.combinePartialSignatures
import perun_network.ecdsa_threshold.sign.presign.*
import java.math.BigInteger
import kotlin.test.*


class PresignTest {
    @Test
    fun testThresholdSign() {
        val n = 5 // Number of total parties.
        val t = 3 // Threshold of minimum required signers.

        // Generate Precomputations (Assuming the secret primes are precomputed).
        val (ids, secretPrecomps, publicPrecomps) = getSamplePrecomputations(n, t) // Use generatePrecomputation instead to generate new safe primes.

        // Message
        val message = "hello"
        val hash = SHA256().digest(message.toByteArray())

        // Determine signerIds
        val signerIds = randomSignerIDs(ids, t)
        val publicKey = publicKeyFromShares(signerIds, publicPrecomps)
        val (scaledPrecomps, scaledPublics, publicPoint) = scalePrecomputations(signerIds, secretPrecomps, publicPrecomps)
        assertEquals(publicKey, publicPoint.toPublicKey())

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

        // PRESIGN ROUND 2
        val bigGammaShares = mutableMapOf<Int, Point>()
        val presignRound2AllBroadcasts = mutableMapOf<Int, Map<Int, PresignRound2Broadcast>>()
        for (i in signerIds) {
            val presignRound1Broadcasts = filterIncomingBroadcast(i, presignRound1AllBroadcasts)
            presignRound2AllBroadcasts[i] = signers[i]!!.presignRound2(signerIds, Ks, presignRound1Broadcasts)

            bigGammaShares[i] = signers[i]!!.bigGammaShare!!
        }


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

        // PROCESS PRESIGN OUTPUTS
        for (i in signerIds) {
            val presignRound3Broadcasts = filterIncomingBroadcast(i, presignRound3AllBroadcasts)
            signers[i]!!.processPresignOutput(signerIds, presignRound3Broadcasts, elGamalPublics, deltaShares, bigDeltaShares)
        }

        // ** PARTIAL SIGNING **
        val partialSignatures = mutableListOf<PartialSignature>()

        for (i in signerIds) {
            partialSignatures.add(signers[i]!!.partialSignMessage(scaledPublics[i]!!.ssid, hash))
        }


        // ** ECDSA SIGNING **
        val ecdsaSignature= combinePartialSignatures(signers[signerIds[0]]!!.bigR!!, partialSignatures, publicPoint, hash)

        assertTrue(ecdsaSignature.verifySecp256k1(hash, publicKey), "failed to convert and verified ecdsa signature")
    }

    @Test
    fun testPresignRound2Fails() {
        val n = 5 // Number of total parties.
        val t = 3 // Threshold of minimum required signers.

        // Generate Precomputations (Assuming the secret primes are precomputed).
        val (ids, secretPrecomps, publicPrecomps) = getSamplePrecomputations(n, t) // Use generatePrecomputation instead to generate new safe primes.

        // Message
        val message = "hello"
        SHA256().digest(message.toByteArray())

        // Determine signerIds
        val signerIds = randomSignerIDs(ids, t)
        val publicKey = publicKeyFromShares(signerIds, publicPrecomps)
        val (scaledPrecomps, scaledPublics, publicPoint) = scalePrecomputations(signerIds, secretPrecomps, publicPrecomps)
        assertEquals(publicKey, publicPoint.toPublicKey())

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

        // PRESIGN ROUND 2
        mutableMapOf<Int, Point>()
        val presignRound2AllBroadcasts = mutableMapOf<Int, Map<Int, PresignRound2Broadcast>>()

        assertFailsWith<NullPointerException> {
            for (i in signerIds) {
                val presignRound1Broadcasts = filterIncomingBroadcast(i, presignRound1AllBroadcasts)
                val modifiedId = signerIds.get((signerIds.indexOf(i)+1)%signerIds.size)
                val modifiedRound1Broadcasts = presignRound1Broadcasts.toMutableMap().filterKeys { id -> id == modifiedId }
                presignRound2AllBroadcasts[i] = signers[i]!!.presignRound2(signerIds, Ks, modifiedRound1Broadcasts)
            }
        }

        assertFailsWith<PresignException> {
            for (i in signerIds) {
                val presignRound1Broadcasts = filterIncomingBroadcast(i, presignRound1AllBroadcasts)
                val modifiedId = signerIds.get((signerIds.indexOf(i)+1)%signerIds.size)
                val modifiedRound1Broadcasts = presignRound1Broadcasts.toMutableMap()
                modifiedRound1Broadcasts[modifiedId] = PresignRound1Broadcast(
                    ssid = generateSessionId(),
                    from = modifiedRound1Broadcasts[modifiedId]!!.from,
                    to = modifiedRound1Broadcasts[modifiedId]!!.to,
                    K = modifiedRound1Broadcasts[modifiedId]!!.K,
                    G = modifiedRound1Broadcasts[modifiedId]!!.G,
                    elGamalPublic = modifiedRound1Broadcasts[modifiedId]!!.elGamalPublic,
                    proof0 = modifiedRound1Broadcasts[modifiedId]!!.proof0,
                    proof1 = modifiedRound1Broadcasts[modifiedId]!!.proof1,
                )
                presignRound2AllBroadcasts[i] = signers[i]!!.presignRound2(signerIds, Ks, modifiedRound1Broadcasts)
            }
        }

        assertFailsWith<PresignException> {
            for (i in signerIds) {
                val presignRound1Broadcasts = filterIncomingBroadcast(i, presignRound1AllBroadcasts)
                val modifiedId = signerIds.get((signerIds.indexOf(i)+1)%signerIds.size)
                val copyId = signerIds.get((signerIds.indexOf(i)+2)%signerIds.size)
                val modifiedRound1Broadcasts = presignRound1Broadcasts.toMutableMap()
                modifiedRound1Broadcasts[modifiedId] = PresignRound1Broadcast(
                    ssid = modifiedRound1Broadcasts[modifiedId]!!.ssid,
                    from = modifiedRound1Broadcasts[copyId]!!.from,
                    to = modifiedRound1Broadcasts[modifiedId]!!.to,
                    K = modifiedRound1Broadcasts[modifiedId]!!.K,
                    G = modifiedRound1Broadcasts[modifiedId]!!.G,
                    elGamalPublic = modifiedRound1Broadcasts[modifiedId]!!.elGamalPublic,
                    proof0 = modifiedRound1Broadcasts[modifiedId]!!.proof0,
                    proof1 = modifiedRound1Broadcasts[modifiedId]!!.proof1,
                )
                presignRound2AllBroadcasts[i] = signers[i]!!.presignRound2(signerIds, Ks, modifiedRound1Broadcasts)
            }
        }

        assertFailsWith<PresignException> {
            for (i in signerIds) {
                val presignRound1Broadcasts = filterIncomingBroadcast(i, presignRound1AllBroadcasts)
                val modifiedId = signerIds.get((signerIds.indexOf(i)+1)%signerIds.size)
                val copyId = signerIds.get((signerIds.indexOf(i)+2)%signerIds.size)
                val modifiedRound1Broadcasts = presignRound1Broadcasts.toMutableMap()
                modifiedRound1Broadcasts[modifiedId] = PresignRound1Broadcast(
                    ssid = modifiedRound1Broadcasts[modifiedId]!!.ssid,
                    from = modifiedRound1Broadcasts[modifiedId]!!.from,
                    to = copyId,
                    K = modifiedRound1Broadcasts[modifiedId]!!.K,
                    G = modifiedRound1Broadcasts[modifiedId]!!.G,
                    elGamalPublic = modifiedRound1Broadcasts[modifiedId]!!.elGamalPublic,
                    proof0 = modifiedRound1Broadcasts[modifiedId]!!.proof0,
                    proof1 = modifiedRound1Broadcasts[modifiedId]!!.proof1,
                )
                presignRound2AllBroadcasts[i] = signers[i]!!.presignRound2(signerIds, Ks, modifiedRound1Broadcasts)
            }
        }

        assertFailsWith<PresignException> {
            for (i in signerIds) {
                val presignRound1Broadcasts = filterIncomingBroadcast(i, presignRound1AllBroadcasts)
                val modifiedId = signerIds.get((signerIds.indexOf(i)+1)%signerIds.size)
                val copyId = signerIds.get((signerIds.indexOf(i)+2)%signerIds.size)
                val modifiedRound1Broadcasts = presignRound1Broadcasts.toMutableMap()
                modifiedRound1Broadcasts[modifiedId] = PresignRound1Broadcast(
                    ssid = modifiedRound1Broadcasts[modifiedId]!!.ssid,
                    from = modifiedRound1Broadcasts[modifiedId]!!.from,
                    to = modifiedRound1Broadcasts[modifiedId]!!.to,
                    K = modifiedRound1Broadcasts[copyId]!!.K,
                    G = modifiedRound1Broadcasts[modifiedId]!!.G,
                    elGamalPublic = modifiedRound1Broadcasts[modifiedId]!!.elGamalPublic,
                    proof0 = modifiedRound1Broadcasts[modifiedId]!!.proof0,
                    proof1 = modifiedRound1Broadcasts[modifiedId]!!.proof1,
                )
                presignRound2AllBroadcasts[i] = signers[i]!!.presignRound2(signerIds, Ks, modifiedRound1Broadcasts)
            }
        }

        assertFailsWith<PresignException> {
            for (i in signerIds) {
                val presignRound1Broadcasts = filterIncomingBroadcast(i, presignRound1AllBroadcasts)
                val modifiedId = signerIds.get((signerIds.indexOf(i)+1)%signerIds.size)
                val copyId = signerIds.get((signerIds.indexOf(i)+2)%signerIds.size)
                val modifiedRound1Broadcasts = presignRound1Broadcasts.toMutableMap()
                modifiedRound1Broadcasts[modifiedId] = PresignRound1Broadcast(
                    ssid = modifiedRound1Broadcasts[modifiedId]!!.ssid,
                    from = modifiedRound1Broadcasts[modifiedId]!!.from,
                    to = modifiedRound1Broadcasts[modifiedId]!!.to,
                    K = modifiedRound1Broadcasts[modifiedId]!!.K,
                    G = modifiedRound1Broadcasts[copyId]!!.G,
                    elGamalPublic = modifiedRound1Broadcasts[modifiedId]!!.elGamalPublic,
                    proof0 = modifiedRound1Broadcasts[modifiedId]!!.proof0,
                    proof1 = modifiedRound1Broadcasts[modifiedId]!!.proof1,
                )
                presignRound2AllBroadcasts[i] = signers[i]!!.presignRound2(signerIds, Ks, modifiedRound1Broadcasts)
            }
        }

        assertFailsWith<PresignException> {
            for (i in signerIds) {
                val presignRound1Broadcasts = filterIncomingBroadcast(i, presignRound1AllBroadcasts)
                val modifiedId = signerIds.get((signerIds.indexOf(i)+1)%signerIds.size)
                val copyId = signerIds.get((signerIds.indexOf(i)+2)%signerIds.size)
                val modifiedRound1Broadcasts = presignRound1Broadcasts.toMutableMap()
                modifiedRound1Broadcasts[modifiedId] = PresignRound1Broadcast(
                    ssid = modifiedRound1Broadcasts[modifiedId]!!.ssid,
                    from = modifiedRound1Broadcasts[modifiedId]!!.from,
                    to = modifiedRound1Broadcasts[modifiedId]!!.to,
                    K = modifiedRound1Broadcasts[modifiedId]!!.K,
                    G = modifiedRound1Broadcasts[modifiedId]!!.G,
                    elGamalPublic = modifiedRound1Broadcasts[copyId]!!.elGamalPublic,
                    proof0 = modifiedRound1Broadcasts[modifiedId]!!.proof0,
                    proof1 = modifiedRound1Broadcasts[modifiedId]!!.proof1,
                )
                presignRound2AllBroadcasts[i] = signers[i]!!.presignRound2(signerIds, Ks, modifiedRound1Broadcasts)
            }
        }

        assertFailsWith<PresignException> {
            for (i in signerIds) {
                val presignRound1Broadcasts = filterIncomingBroadcast(i, presignRound1AllBroadcasts)
                val modifiedId = signerIds.get((signerIds.indexOf(i)+1)%signerIds.size)
                val copyId = signerIds.get((signerIds.indexOf(i)+2)%signerIds.size)
                val modifiedRound1Broadcasts = presignRound1Broadcasts.toMutableMap()
                modifiedRound1Broadcasts[modifiedId] = PresignRound1Broadcast(
                    ssid = modifiedRound1Broadcasts[modifiedId]!!.ssid,
                    from = modifiedRound1Broadcasts[modifiedId]!!.from,
                    to = modifiedRound1Broadcasts[modifiedId]!!.to,
                    K = modifiedRound1Broadcasts[modifiedId]!!.K,
                    G = modifiedRound1Broadcasts[modifiedId]!!.G,
                    elGamalPublic = modifiedRound1Broadcasts[modifiedId]!!.elGamalPublic,
                    proof0 = modifiedRound1Broadcasts[copyId]!!.proof0,
                    proof1 = modifiedRound1Broadcasts[modifiedId]!!.proof1,
                )
                presignRound2AllBroadcasts[i] = signers[i]!!.presignRound2(signerIds, Ks, modifiedRound1Broadcasts)
            }
        }

        assertFailsWith<PresignException> {
            for (i in signerIds) {
                val presignRound1Broadcasts = filterIncomingBroadcast(i, presignRound1AllBroadcasts)
                val modifiedId = signerIds.get((signerIds.indexOf(i)+1)%signerIds.size)
                val copyId = signerIds.get((signerIds.indexOf(i)+2)%signerIds.size)
                val modifiedRound1Broadcasts = presignRound1Broadcasts.toMutableMap()
                modifiedRound1Broadcasts[modifiedId] = PresignRound1Broadcast(
                    ssid = modifiedRound1Broadcasts[modifiedId]!!.ssid,
                    from = modifiedRound1Broadcasts[modifiedId]!!.from,
                    to = modifiedRound1Broadcasts[modifiedId]!!.to,
                    K = modifiedRound1Broadcasts[modifiedId]!!.K,
                    G = modifiedRound1Broadcasts[modifiedId]!!.G,
                    elGamalPublic = modifiedRound1Broadcasts[modifiedId]!!.elGamalPublic,
                    proof0 = modifiedRound1Broadcasts[modifiedId]!!.proof0,
                    proof1 = modifiedRound1Broadcasts[copyId]!!.proof1,
                )
                presignRound2AllBroadcasts[i] = signers[i]!!.presignRound2(signerIds, Ks, modifiedRound1Broadcasts)
            }
        }
    }

    @Test
    fun testPresignRound3Fails() {
        val n = 5 // Number of total parties.
        val t = 3 // Threshold of minimum required signers.

        // Generate Precomputations (Assuming the secret primes are precomputed).
        val (ids, secretPrecomps, publicPrecomps) = getSamplePrecomputations(n, t) // Use generatePrecomputation instead to generate new safe primes.

        // Message
        val message = "hello"
        SHA256().digest(message.toByteArray())

        // Determine signerIds
        val signerIds = randomSignerIDs(ids, t)
        val publicKey = publicKeyFromShares(signerIds, publicPrecomps)
        val (scaledPrecomps, scaledPublics, publicPoint) = scalePrecomputations(signerIds, secretPrecomps, publicPrecomps)
        assertEquals(publicKey, publicPoint.toPublicKey())

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

        // PRESIGN ROUND 2
        val bigGammaShares = mutableMapOf<Int, Point>()
        val presignRound2AllBroadcasts = mutableMapOf<Int, Map<Int, PresignRound2Broadcast>>()
        for (i in signerIds) {
            val presignRound1Broadcasts = filterIncomingBroadcast(i, presignRound1AllBroadcasts)
            presignRound2AllBroadcasts[i] = signers[i]!!.presignRound2(signerIds, Ks, presignRound1Broadcasts)

            bigGammaShares[i] = signers[i]!!.bigGammaShare!!
        }

        // PRESIGN ROUND 3
        assertFailsWith<PresignException> {
            val elGamal2 = elGamalPublics.toMap().toMutableMap()
            elGamal2[signerIds[0]] = elGamal2[signerIds.last()]!!
            val presignRound3AllBroadcasts = mutableMapOf<Int, Map<Int, PresignRound3Broadcast>>()
            val deltaShares = mutableMapOf<Int,BigInteger>()
            val bigDeltaShares = mutableMapOf<Int,Point>()
            for (i in signerIds) {
                val presignRound2Broadcasts = filterIncomingBroadcast(i, presignRound2AllBroadcasts)
                presignRound3AllBroadcasts[i] = signers[i]!!.presignRound3(signerIds, bigGammaShares, elGamal2, presignRound2Broadcasts)
                deltaShares[i] = signers[i]!!.deltaShare!!
                bigDeltaShares[i] = signers[i]!!.bigDeltaShare!!
            }
        }

        assertFailsWith<PresignException> {
            val presignRound3AllBroadcasts = mutableMapOf<Int, Map<Int, PresignRound3Broadcast>>()
            for (i in signerIds) {
                val presignRound2Broadcasts = filterIncomingBroadcast(i, presignRound2AllBroadcasts)
                val modifiedId = signerIds.get((signerIds.indexOf(i)+1)%signerIds.size)
                val modifiedRound2Broadcasts = presignRound2Broadcasts.toMutableMap()
                modifiedRound2Broadcasts[modifiedId] = PresignRound2Broadcast(
                    ssid = generateSessionId(),
                    from = modifiedRound2Broadcasts[modifiedId]!!.from,
                    to = modifiedRound2Broadcasts[modifiedId]!!.to,
                    bigGammaShare = modifiedRound2Broadcasts[modifiedId]!!.bigGammaShare,
                    deltaD = modifiedRound2Broadcasts[modifiedId]!!.deltaD,
                    deltaF = modifiedRound2Broadcasts[modifiedId]!!.deltaF,
                    deltaProof = modifiedRound2Broadcasts[modifiedId]!!.deltaProof,
                    chiD = modifiedRound2Broadcasts[modifiedId]!!.chiD,
                    chiF = modifiedRound2Broadcasts[modifiedId]!!.chiF,
                    chiProof = modifiedRound2Broadcasts[modifiedId]!!.chiProof,
                    elogProof = modifiedRound2Broadcasts[modifiedId]!!.elogProof,
                    chiBeta = modifiedRound2Broadcasts[modifiedId]!!.chiBeta,
                    deltaBeta = modifiedRound2Broadcasts[modifiedId]!!.deltaBeta,
                )
                presignRound3AllBroadcasts[i] = signers[i]!!.presignRound3(signerIds, bigGammaShares, elGamalPublics, modifiedRound2Broadcasts)
            }
        }

        assertFailsWith<PresignException> {
            val presignRound3AllBroadcasts = mutableMapOf<Int, Map<Int, PresignRound3Broadcast>>()
            for (i in signerIds) {
                val presignRound2Broadcasts = filterIncomingBroadcast(i, presignRound2AllBroadcasts)
                val modifiedId = signerIds.get((signerIds.indexOf(i)+1)%signerIds.size)
                val copyId = signerIds.get((signerIds.indexOf(i)+2)%signerIds.size)
                val modifiedRound2Broadcasts = presignRound2Broadcasts.toMutableMap()
                modifiedRound2Broadcasts[modifiedId] = PresignRound2Broadcast(
                    ssid = modifiedRound2Broadcasts[modifiedId]!!.ssid,
                    from = modifiedRound2Broadcasts[copyId]!!.from,
                    to = modifiedRound2Broadcasts[modifiedId]!!.to,
                    bigGammaShare = modifiedRound2Broadcasts[modifiedId]!!.bigGammaShare,
                    deltaD = modifiedRound2Broadcasts[modifiedId]!!.deltaD,
                    deltaF = modifiedRound2Broadcasts[modifiedId]!!.deltaF,
                    deltaProof = modifiedRound2Broadcasts[modifiedId]!!.deltaProof,
                    chiD = modifiedRound2Broadcasts[modifiedId]!!.chiD,
                    chiF = modifiedRound2Broadcasts[modifiedId]!!.chiF,
                    chiProof = modifiedRound2Broadcasts[modifiedId]!!.chiProof,
                    elogProof = modifiedRound2Broadcasts[modifiedId]!!.elogProof,
                    chiBeta = modifiedRound2Broadcasts[modifiedId]!!.chiBeta,
                    deltaBeta = modifiedRound2Broadcasts[modifiedId]!!.deltaBeta,
                )
                presignRound3AllBroadcasts[i] = signers[i]!!.presignRound3(signerIds, bigGammaShares, elGamalPublics, modifiedRound2Broadcasts)
            }
        }

        assertFailsWith<PresignException> {
            val presignRound3AllBroadcasts = mutableMapOf<Int, Map<Int, PresignRound3Broadcast>>()
            for (i in signerIds) {
                val presignRound2Broadcasts = filterIncomingBroadcast(i, presignRound2AllBroadcasts)
                val modifiedId = signerIds.get((signerIds.indexOf(i)+1)%signerIds.size)
                val copyId = signerIds.get((signerIds.indexOf(i)+2)%signerIds.size)
                val modifiedRound2Broadcasts = presignRound2Broadcasts.toMutableMap()
                modifiedRound2Broadcasts[modifiedId] = PresignRound2Broadcast(
                    ssid = modifiedRound2Broadcasts[modifiedId]!!.ssid,
                    from = modifiedRound2Broadcasts[modifiedId]!!.from,
                    to = copyId,
                    bigGammaShare = modifiedRound2Broadcasts[modifiedId]!!.bigGammaShare,
                    deltaD = modifiedRound2Broadcasts[modifiedId]!!.deltaD,
                    deltaF = modifiedRound2Broadcasts[modifiedId]!!.deltaF,
                    deltaProof = modifiedRound2Broadcasts[modifiedId]!!.deltaProof,
                    chiD = modifiedRound2Broadcasts[modifiedId]!!.chiD,
                    chiF = modifiedRound2Broadcasts[modifiedId]!!.chiF,
                    chiProof = modifiedRound2Broadcasts[modifiedId]!!.chiProof,
                    elogProof = modifiedRound2Broadcasts[modifiedId]!!.elogProof,
                    chiBeta = modifiedRound2Broadcasts[modifiedId]!!.chiBeta,
                    deltaBeta = modifiedRound2Broadcasts[modifiedId]!!.deltaBeta,
                )
                presignRound3AllBroadcasts[i] = signers[i]!!.presignRound3(signerIds, bigGammaShares, elGamalPublics, modifiedRound2Broadcasts)
            }
        }

        assertFailsWith<PresignException> {
            val presignRound3AllBroadcasts = mutableMapOf<Int, Map<Int, PresignRound3Broadcast>>()
            for (i in signerIds) {
                val presignRound2Broadcasts = filterIncomingBroadcast(i, presignRound2AllBroadcasts)
                val modifiedId = signerIds.get((signerIds.indexOf(i)+1)%signerIds.size)
                val copyId = signerIds.get((signerIds.indexOf(i)+2)%signerIds.size)
                val modifiedRound2Broadcasts = presignRound2Broadcasts.toMutableMap()
                modifiedRound2Broadcasts[modifiedId] = PresignRound2Broadcast(
                    ssid = modifiedRound2Broadcasts[modifiedId]!!.ssid,
                    from = modifiedRound2Broadcasts[modifiedId]!!.from,
                    to = modifiedRound2Broadcasts[modifiedId]!!.to,
                    bigGammaShare = modifiedRound2Broadcasts[copyId]!!.bigGammaShare,
                    deltaD = modifiedRound2Broadcasts[modifiedId]!!.deltaD,
                    deltaF = modifiedRound2Broadcasts[modifiedId]!!.deltaF,
                    deltaProof = modifiedRound2Broadcasts[modifiedId]!!.deltaProof,
                    chiD = modifiedRound2Broadcasts[modifiedId]!!.chiD,
                    chiF = modifiedRound2Broadcasts[modifiedId]!!.chiF,
                    chiProof = modifiedRound2Broadcasts[modifiedId]!!.chiProof,
                    elogProof = modifiedRound2Broadcasts[modifiedId]!!.elogProof,
                    chiBeta = modifiedRound2Broadcasts[modifiedId]!!.chiBeta,
                    deltaBeta = modifiedRound2Broadcasts[modifiedId]!!.deltaBeta,
                )
                presignRound3AllBroadcasts[i] = signers[i]!!.presignRound3(signerIds, bigGammaShares, elGamalPublics, modifiedRound2Broadcasts)
            }
        }

        assertFailsWith<PresignException> {
            val presignRound3AllBroadcasts = mutableMapOf<Int, Map<Int, PresignRound3Broadcast>>()
            for (i in signerIds) {
                val presignRound2Broadcasts = filterIncomingBroadcast(i, presignRound2AllBroadcasts)
                val modifiedId = signerIds.get((signerIds.indexOf(i)+1)%signerIds.size)
                val copyId = signerIds.get((signerIds.indexOf(i)+2)%signerIds.size)
                val modifiedRound2Broadcasts = presignRound2Broadcasts.toMutableMap()
                modifiedRound2Broadcasts[modifiedId] = PresignRound2Broadcast(
                    ssid = modifiedRound2Broadcasts[modifiedId]!!.ssid,
                    from = modifiedRound2Broadcasts[modifiedId]!!.from,
                    to = modifiedRound2Broadcasts[modifiedId]!!.to,
                    bigGammaShare = modifiedRound2Broadcasts[modifiedId]!!.bigGammaShare,
                    deltaD = modifiedRound2Broadcasts[copyId]!!.deltaD,
                    deltaF = modifiedRound2Broadcasts[modifiedId]!!.deltaF,
                    deltaProof = modifiedRound2Broadcasts[modifiedId]!!.deltaProof,
                    chiD = modifiedRound2Broadcasts[modifiedId]!!.chiD,
                    chiF = modifiedRound2Broadcasts[modifiedId]!!.chiF,
                    chiProof = modifiedRound2Broadcasts[modifiedId]!!.chiProof,
                    elogProof = modifiedRound2Broadcasts[modifiedId]!!.elogProof,
                    chiBeta = modifiedRound2Broadcasts[modifiedId]!!.chiBeta,
                    deltaBeta = modifiedRound2Broadcasts[modifiedId]!!.deltaBeta,
                )
                presignRound3AllBroadcasts[i] = signers[i]!!.presignRound3(signerIds, bigGammaShares, elGamalPublics, modifiedRound2Broadcasts)
            }
        }

        assertFailsWith<PresignException> {
            val presignRound3AllBroadcasts = mutableMapOf<Int, Map<Int, PresignRound3Broadcast>>()
            for (i in signerIds) {
                val presignRound2Broadcasts = filterIncomingBroadcast(i, presignRound2AllBroadcasts)
                val modifiedId = signerIds.get((signerIds.indexOf(i)+1)%signerIds.size)
                val copyId = signerIds.get((signerIds.indexOf(i)+2)%signerIds.size)
                val modifiedRound2Broadcasts = presignRound2Broadcasts.toMutableMap()
                modifiedRound2Broadcasts[modifiedId] = PresignRound2Broadcast(
                    ssid = modifiedRound2Broadcasts[modifiedId]!!.ssid,
                    from = modifiedRound2Broadcasts[modifiedId]!!.from,
                    to = modifiedRound2Broadcasts[modifiedId]!!.to,
                    bigGammaShare = modifiedRound2Broadcasts[modifiedId]!!.bigGammaShare,
                    deltaD = modifiedRound2Broadcasts[modifiedId]!!.deltaD,
                    deltaF = modifiedRound2Broadcasts[copyId]!!.deltaF,
                    deltaProof = modifiedRound2Broadcasts[modifiedId]!!.deltaProof,
                    chiD = modifiedRound2Broadcasts[modifiedId]!!.chiD,
                    chiF = modifiedRound2Broadcasts[modifiedId]!!.chiF,
                    chiProof = modifiedRound2Broadcasts[modifiedId]!!.chiProof,
                    elogProof = modifiedRound2Broadcasts[modifiedId]!!.elogProof,
                    chiBeta = modifiedRound2Broadcasts[modifiedId]!!.chiBeta,
                    deltaBeta = modifiedRound2Broadcasts[modifiedId]!!.deltaBeta,
                )
                presignRound3AllBroadcasts[i] = signers[i]!!.presignRound3(signerIds, bigGammaShares, elGamalPublics, modifiedRound2Broadcasts)
            }
        }

        assertFailsWith<PresignException> {
            val presignRound3AllBroadcasts = mutableMapOf<Int, Map<Int, PresignRound3Broadcast>>()
            for (i in signerIds) {
                val presignRound2Broadcasts = filterIncomingBroadcast(i, presignRound2AllBroadcasts)
                val modifiedId = signerIds.get((signerIds.indexOf(i)+1)%signerIds.size)
                val copyId = signerIds.get((signerIds.indexOf(i)+2)%signerIds.size)
                val modifiedRound2Broadcasts = presignRound2Broadcasts.toMutableMap()
                modifiedRound2Broadcasts[modifiedId] = PresignRound2Broadcast(
                    ssid = modifiedRound2Broadcasts[modifiedId]!!.ssid,
                    from = modifiedRound2Broadcasts[modifiedId]!!.from,
                    to = modifiedRound2Broadcasts[modifiedId]!!.to,
                    bigGammaShare = modifiedRound2Broadcasts[modifiedId]!!.bigGammaShare,
                    deltaD = modifiedRound2Broadcasts[modifiedId]!!.deltaD,
                    deltaF = modifiedRound2Broadcasts[modifiedId]!!.deltaF,
                    deltaProof = modifiedRound2Broadcasts[copyId]!!.deltaProof,
                    chiD = modifiedRound2Broadcasts[modifiedId]!!.chiD,
                    chiF = modifiedRound2Broadcasts[modifiedId]!!.chiF,
                    chiProof = modifiedRound2Broadcasts[modifiedId]!!.chiProof,
                    elogProof = modifiedRound2Broadcasts[modifiedId]!!.elogProof,
                    chiBeta = modifiedRound2Broadcasts[modifiedId]!!.chiBeta,
                    deltaBeta = modifiedRound2Broadcasts[modifiedId]!!.deltaBeta,
                )
                presignRound3AllBroadcasts[i] = signers[i]!!.presignRound3(signerIds, bigGammaShares, elGamalPublics, modifiedRound2Broadcasts)
            }
        }

        assertFailsWith<PresignException> {
            val presignRound3AllBroadcasts = mutableMapOf<Int, Map<Int, PresignRound3Broadcast>>()
            for (i in signerIds) {
                val presignRound2Broadcasts = filterIncomingBroadcast(i, presignRound2AllBroadcasts)
                val modifiedId = signerIds.get((signerIds.indexOf(i)+1)%signerIds.size)
                val copyId = signerIds.get((signerIds.indexOf(i)+2)%signerIds.size)
                val modifiedRound2Broadcasts = presignRound2Broadcasts.toMutableMap()
                modifiedRound2Broadcasts[modifiedId] = PresignRound2Broadcast(
                    ssid = modifiedRound2Broadcasts[modifiedId]!!.ssid,
                    from = modifiedRound2Broadcasts[modifiedId]!!.from,
                    to = modifiedRound2Broadcasts[modifiedId]!!.to,
                    bigGammaShare = modifiedRound2Broadcasts[modifiedId]!!.bigGammaShare,
                    deltaD = modifiedRound2Broadcasts[modifiedId]!!.deltaD,
                    deltaF = modifiedRound2Broadcasts[modifiedId]!!.deltaF,
                    deltaProof = modifiedRound2Broadcasts[modifiedId]!!.deltaProof,
                    chiD = modifiedRound2Broadcasts[copyId]!!.chiD,
                    chiF = modifiedRound2Broadcasts[modifiedId]!!.chiF,
                    chiProof = modifiedRound2Broadcasts[modifiedId]!!.chiProof,
                    elogProof = modifiedRound2Broadcasts[modifiedId]!!.elogProof,
                    chiBeta = modifiedRound2Broadcasts[modifiedId]!!.chiBeta,
                    deltaBeta = modifiedRound2Broadcasts[modifiedId]!!.deltaBeta,
                )
                presignRound3AllBroadcasts[i] = signers[i]!!.presignRound3(signerIds, bigGammaShares, elGamalPublics, modifiedRound2Broadcasts)
            }
        }

        assertFailsWith<PresignException> {
            val presignRound3AllBroadcasts = mutableMapOf<Int, Map<Int, PresignRound3Broadcast>>()
            for (i in signerIds) {
                val presignRound2Broadcasts = filterIncomingBroadcast(i, presignRound2AllBroadcasts)
                val modifiedId = signerIds.get((signerIds.indexOf(i)+1)%signerIds.size)
                val copyId = signerIds.get((signerIds.indexOf(i)+2)%signerIds.size)
                val modifiedRound2Broadcasts = presignRound2Broadcasts.toMutableMap()
                modifiedRound2Broadcasts[modifiedId] = PresignRound2Broadcast(
                    ssid = modifiedRound2Broadcasts[modifiedId]!!.ssid,
                    from = modifiedRound2Broadcasts[modifiedId]!!.from,
                    to = modifiedRound2Broadcasts[modifiedId]!!.to,
                    bigGammaShare = modifiedRound2Broadcasts[modifiedId]!!.bigGammaShare,
                    deltaD = modifiedRound2Broadcasts[modifiedId]!!.deltaD,
                    deltaF = modifiedRound2Broadcasts[modifiedId]!!.deltaF,
                    deltaProof = modifiedRound2Broadcasts[modifiedId]!!.deltaProof,
                    chiD = modifiedRound2Broadcasts[modifiedId]!!.chiD,
                    chiF = modifiedRound2Broadcasts[copyId]!!.chiF,
                    chiProof = modifiedRound2Broadcasts[modifiedId]!!.chiProof,
                    elogProof = modifiedRound2Broadcasts[modifiedId]!!.elogProof,
                    chiBeta = modifiedRound2Broadcasts[modifiedId]!!.chiBeta,
                    deltaBeta = modifiedRound2Broadcasts[modifiedId]!!.deltaBeta,
                )
                presignRound3AllBroadcasts[i] = signers[i]!!.presignRound3(signerIds, bigGammaShares, elGamalPublics, modifiedRound2Broadcasts)
            }
        }

        assertFailsWith<PresignException> {
            val presignRound3AllBroadcasts = mutableMapOf<Int, Map<Int, PresignRound3Broadcast>>()
            for (i in signerIds) {
                val presignRound2Broadcasts = filterIncomingBroadcast(i, presignRound2AllBroadcasts)
                val modifiedId = signerIds.get((signerIds.indexOf(i)+1)%signerIds.size)
                val copyId = signerIds.get((signerIds.indexOf(i)+2)%signerIds.size)
                val modifiedRound2Broadcasts = presignRound2Broadcasts.toMutableMap()
                modifiedRound2Broadcasts[modifiedId] = PresignRound2Broadcast(
                    ssid = modifiedRound2Broadcasts[modifiedId]!!.ssid,
                    from = modifiedRound2Broadcasts[modifiedId]!!.from,
                    to = modifiedRound2Broadcasts[modifiedId]!!.to,
                    bigGammaShare = modifiedRound2Broadcasts[modifiedId]!!.bigGammaShare,
                    deltaD = modifiedRound2Broadcasts[modifiedId]!!.deltaD,
                    deltaF = modifiedRound2Broadcasts[modifiedId]!!.deltaF,
                    deltaProof = modifiedRound2Broadcasts[modifiedId]!!.deltaProof,
                    chiD = modifiedRound2Broadcasts[modifiedId]!!.chiD,
                    chiF = modifiedRound2Broadcasts[modifiedId]!!.chiF,
                    chiProof = modifiedRound2Broadcasts[copyId]!!.chiProof,
                    elogProof = modifiedRound2Broadcasts[modifiedId]!!.elogProof,
                    chiBeta = modifiedRound2Broadcasts[modifiedId]!!.chiBeta,
                    deltaBeta = modifiedRound2Broadcasts[modifiedId]!!.deltaBeta,
                )
                presignRound3AllBroadcasts[i] = signers[i]!!.presignRound3(signerIds, bigGammaShares, elGamalPublics, modifiedRound2Broadcasts)
            }
        }

        assertFailsWith<PresignException> {
            val presignRound3AllBroadcasts = mutableMapOf<Int, Map<Int, PresignRound3Broadcast>>()
            for (i in signerIds) {
                val presignRound2Broadcasts = filterIncomingBroadcast(i, presignRound2AllBroadcasts)
                val modifiedId = signerIds.get((signerIds.indexOf(i)+1)%signerIds.size)
                val copyId = signerIds.get((signerIds.indexOf(i)+2)%signerIds.size)
                val modifiedRound2Broadcasts = presignRound2Broadcasts.toMutableMap()
                modifiedRound2Broadcasts[modifiedId] = PresignRound2Broadcast(
                    ssid = modifiedRound2Broadcasts[modifiedId]!!.ssid,
                    from = modifiedRound2Broadcasts[modifiedId]!!.from,
                    to = modifiedRound2Broadcasts[modifiedId]!!.to,
                    bigGammaShare = modifiedRound2Broadcasts[modifiedId]!!.bigGammaShare,
                    deltaD = modifiedRound2Broadcasts[modifiedId]!!.deltaD,
                    deltaF = modifiedRound2Broadcasts[modifiedId]!!.deltaF,
                    deltaProof = modifiedRound2Broadcasts[modifiedId]!!.deltaProof,
                    chiD = modifiedRound2Broadcasts[modifiedId]!!.chiD,
                    chiF = modifiedRound2Broadcasts[modifiedId]!!.chiF,
                    chiProof = modifiedRound2Broadcasts[modifiedId]!!.chiProof,
                    elogProof = modifiedRound2Broadcasts[copyId]!!.elogProof,
                    chiBeta = modifiedRound2Broadcasts[modifiedId]!!.chiBeta,
                    deltaBeta = modifiedRound2Broadcasts[modifiedId]!!.deltaBeta,
                )
                presignRound3AllBroadcasts[i] = signers[i]!!.presignRound3(signerIds, bigGammaShares, elGamalPublics, modifiedRound2Broadcasts)
            }
        }

    }

    @Test
    fun testPresignFails() {
        val n = 5 // Number of total parties.
        val t = 3 // Threshold of minimum required signers.

        // Generate Precomputations (Assuming the secret primes are precomputed).
        val (ids, secretPrecomps, publicPrecomps) = getSamplePrecomputations(n, t) // Use generatePrecomputation instead to generate new safe primes.

        // Message
        val message = "hello"
        SHA256().digest(message.toByteArray())

        // Determine signerIds
        val signerIds = randomSignerIDs(ids, t)
        val publicKey = publicKeyFromShares(signerIds, publicPrecomps)
        val (scaledPrecomps, scaledPublics, publicPoint) = scalePrecomputations(signerIds, secretPrecomps, publicPrecomps)
        assertEquals(publicKey, publicPoint.toPublicKey())

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

        // PRESIGN ROUND 2
        val bigGammaShares = mutableMapOf<Int, Point>()
        val presignRound2AllBroadcasts = mutableMapOf<Int, Map<Int, PresignRound2Broadcast>>()
        for (i in signerIds) {
            val presignRound1Broadcasts = filterIncomingBroadcast(i, presignRound1AllBroadcasts)
            presignRound2AllBroadcasts[i] = signers[i]!!.presignRound2(signerIds, Ks, presignRound1Broadcasts)

            bigGammaShares[i] = signers[i]!!.bigGammaShare!!
        }

        // PRESIGN ROUND 3
        assertFailsWith<PresignException> {
            val elGamal2 = elGamalPublics.toMap().toMutableMap()
            elGamal2[signerIds[0]] = elGamal2[signerIds.last()]!!
            val presignRound3AllBroadcasts = mutableMapOf<Int, Map<Int, PresignRound3Broadcast>>()
            val deltaShares = mutableMapOf<Int,BigInteger>()
            val bigDeltaShares = mutableMapOf<Int,Point>()
            for (i in signerIds) {
                val presignRound2Broadcasts = filterIncomingBroadcast(i, presignRound2AllBroadcasts)
                presignRound3AllBroadcasts[i] = signers[i]!!.presignRound3(signerIds, bigGammaShares, elGamal2, presignRound2Broadcasts)
                deltaShares[i] = signers[i]!!.deltaShare!!
                bigDeltaShares[i] = signers[i]!!.bigDeltaShare!!
            }
        }


        val presignRound3AllBroadcasts = mutableMapOf<Int, Map<Int, PresignRound3Broadcast>>()
        val deltaShares = mutableMapOf<Int,BigInteger>()
        val bigDeltaShares = mutableMapOf<Int,Point>()
        for (i in signerIds) {
            val presignRound2Broadcasts = filterIncomingBroadcast(i, presignRound2AllBroadcasts)
            presignRound3AllBroadcasts[i] = signers[i]!!.presignRound3(signerIds, bigGammaShares, elGamalPublics, presignRound2Broadcasts)
            deltaShares[i] = signers[i]!!.deltaShare!!
            bigDeltaShares[i] = signers[i]!!.bigDeltaShare!!
        }


        // PROCESS PRESIGN OUTPUT
        assertFailsWith<NullPointerException> {
            for (i in signerIds) {
                val presignRound3Broadcasts = filterIncomingBroadcast(i, presignRound3AllBroadcasts)
                val modifiedId = signerIds.get((signerIds.indexOf(i)+1)%signerIds.size)
                val modifiedRound3Broadcasts = presignRound3Broadcasts.toMutableMap().filterKeys{id -> id == modifiedId}
                signers[i]!!.processPresignOutput(
                    signerIds,
                    modifiedRound3Broadcasts,
                    elGamalPublics,
                    deltaShares,
                    bigDeltaShares
                )
            }
        }

        assertFailsWith<PresignException> {
            for (i in signerIds) {
                val presignRound3Broadcasts = filterIncomingBroadcast(i, presignRound3AllBroadcasts)
                val modifiedRound3Broadcast = presignRound3Broadcasts.toMutableMap()
                val modifiedId = signerIds.get((signerIds.indexOf(i)+1)%signerIds.size)
                modifiedRound3Broadcast[modifiedId] = PresignRound3Broadcast(
                    ssid = generateSessionId(),
                    from = modifiedRound3Broadcast[modifiedId]!!.from,
                    to = modifiedRound3Broadcast[modifiedId]!!.to,
                    chiShare = modifiedRound3Broadcast[modifiedId]!!.chiShare,
                    deltaShare = modifiedRound3Broadcast[modifiedId]!!.deltaShare,
                    bigDeltaShare = modifiedRound3Broadcast[modifiedId]!!.bigDeltaShare,
                    gamma = modifiedRound3Broadcast[modifiedId]!!.gamma,
                    elogProof = modifiedRound3Broadcast[modifiedId]!!.elogProof
                )
                signers[i]!!.processPresignOutput(
                    signerIds,
                    modifiedRound3Broadcast,
                    elGamalPublics,
                    deltaShares,
                    bigDeltaShares
                )
            }
        }

        assertFailsWith<PresignException> {
            for (i in signerIds) {
                val presignRound3Broadcasts = filterIncomingBroadcast(i, presignRound3AllBroadcasts)
                val modifiedRound3Broadcast = presignRound3Broadcasts.toMutableMap()
                val modifiedId = signerIds.get((signerIds.indexOf(i)+1)%signerIds.size)
                modifiedRound3Broadcast[modifiedId] = PresignRound3Broadcast(
                    ssid = modifiedRound3Broadcast[modifiedId]!!.ssid,
                    from = modifiedRound3Broadcast[modifiedId]!!.from + 1,
                    to = modifiedRound3Broadcast[modifiedId]!!.to,
                    chiShare = modifiedRound3Broadcast[modifiedId]!!.chiShare,
                    deltaShare = modifiedRound3Broadcast[modifiedId]!!.deltaShare,
                    bigDeltaShare = modifiedRound3Broadcast[modifiedId]!!.bigDeltaShare,
                    gamma = modifiedRound3Broadcast[modifiedId]!!.gamma,
                    elogProof = modifiedRound3Broadcast[modifiedId]!!.elogProof
                )
                signers[i]!!.processPresignOutput(
                    signerIds,
                    modifiedRound3Broadcast,
                    elGamalPublics,
                    deltaShares,
                    bigDeltaShares
                )
            }
        }

        assertFailsWith<PresignException> {
            for (i in signerIds) {
                val presignRound3Broadcasts = filterIncomingBroadcast(i, presignRound3AllBroadcasts)
                val modifiedRound3Broadcast = presignRound3Broadcasts.toMutableMap()
                val modifiedId = signerIds.get((signerIds.indexOf(i)+1)%signerIds.size)
                val copyId = signerIds.get((signerIds.indexOf(i)+2)%signerIds.size)
                modifiedRound3Broadcast[modifiedId] = PresignRound3Broadcast(
                    ssid = modifiedRound3Broadcast[modifiedId]!!.ssid,
                    from = modifiedRound3Broadcast[modifiedId]!!.from,
                    to = modifiedRound3Broadcast[copyId]!!.to+5,
                    chiShare = modifiedRound3Broadcast[modifiedId]!!.chiShare,
                    deltaShare = modifiedRound3Broadcast[modifiedId]!!.deltaShare,
                    bigDeltaShare = modifiedRound3Broadcast[modifiedId]!!.bigDeltaShare,
                    gamma = modifiedRound3Broadcast[modifiedId]!!.gamma,
                    elogProof = modifiedRound3Broadcast[modifiedId]!!.elogProof
                )
                signers[i]!!.processPresignOutput(
                    signerIds,
                    modifiedRound3Broadcast,
                    elGamalPublics,
                    deltaShares,
                    bigDeltaShares
                )
            }
        }

        assertFailsWith<PresignException> {
            for (i in signerIds) {
                val presignRound3Broadcasts = filterIncomingBroadcast(i, presignRound3AllBroadcasts)
                val modifiedRound3Broadcast = presignRound3Broadcasts.toMutableMap()
                val modifiedId = signerIds.get((signerIds.indexOf(i)+1)%signerIds.size)
                val copyId = signerIds.get((signerIds.indexOf(i)+2)%signerIds.size)
                modifiedRound3Broadcast[modifiedId] = PresignRound3Broadcast(
                    ssid = modifiedRound3Broadcast[modifiedId]!!.ssid,
                    from = modifiedRound3Broadcast[modifiedId]!!.from,
                    to = modifiedRound3Broadcast[modifiedId]!!.to,
                    chiShare = modifiedRound3Broadcast[modifiedId]!!.chiShare,
                    deltaShare = modifiedRound3Broadcast[modifiedId]!!.deltaShare,
                    bigDeltaShare = modifiedRound3Broadcast[modifiedId]!!.bigDeltaShare,
                    gamma = modifiedRound3Broadcast[modifiedId]!!.gamma,
                    elogProof = modifiedRound3Broadcast[copyId]!!.elogProof
                )
                signers[i]!!.processPresignOutput(
                    signerIds,
                    modifiedRound3Broadcast,
                    elGamalPublics,
                    deltaShares,
                    bigDeltaShares
                )
            }
        }

        assertFailsWith<PresignException> {
            elGamalPublics[signerIds[0]] = elGamalPublics[signerIds.last()]!!
            for (i in signerIds) {
                val presignRound3Broadcasts = filterIncomingBroadcast(i, presignRound3AllBroadcasts)
                signers[i]!!.processPresignOutput(
                    signerIds,
                    presignRound3Broadcasts,
                    elGamalPublics,
                    deltaShares,
                    bigDeltaShares
                )
            }
        }

        assertFails {
            elGamalPublics[signerIds[0]] = elGamalPublics[signerIds.last()]!!
            for (i in signerIds) {
                deltaShares[i] = sampleScalar().value
                val presignRound3Broadcasts = filterIncomingBroadcast(i, presignRound3AllBroadcasts)
                signers[i]!!.processPresignOutput(
                    signerIds,
                    presignRound3Broadcasts,
                    elGamalPublics,
                    deltaShares,
                    bigDeltaShares
                )
            }
        }

        assertFails{
            elGamalPublics[signerIds[0]] = elGamalPublics[signerIds.last()]!!
            for (i in signerIds) {
                bigDeltaShares[i] = sampleScalar().actOnBase()
                val presignRound3Broadcasts = filterIncomingBroadcast(i, presignRound3AllBroadcasts)
                signers[i]!!.processPresignOutput(
                    signerIds,
                    presignRound3Broadcasts,
                    elGamalPublics,
                    deltaShares,
                    bigDeltaShares
                )
            }
        }
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
