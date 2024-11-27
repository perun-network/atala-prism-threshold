package sign

import org.junit.jupiter.api.Assertions.assertEquals
import org.kotlincrypto.hash.sha2.SHA256
import perun_network.ecdsa_threshold.ecdsa.PartialSignature
import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.precomp.PublicPrecomputation
import perun_network.ecdsa_threshold.precomp.generateSessionId
import perun_network.ecdsa_threshold.precomp.publicKeyFromShares
import perun_network.ecdsa_threshold.randomSigners
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
import kotlin.test.Test
import kotlin.test.assertFails
import kotlin.test.assertTrue

object SignerTest {
    @Test
    fun testSigner() {
        val n = 5 // Number of total parties.
        val t = 3 // Threshold of minimum required signers.

        val ssid = generateSessionId()
        val parties = mutableMapOf<Int, Signer>()
        for (i in 1..n) {
            parties[i] = Signer(
                id = i,
                ssid = ssid,
                threshold = t,
            )
        }

        keygen(parties)

        val publicPrecomps = aux(parties)

        val signers = randomSigners(parties, t)
        val publicKey = publicKeyFromShares(signers.keys.toList(), publicPrecomps)

        // Scale Secret/Public Precomputations
        val (publicPoint, _) =  scalePrecomputation(signers)
        assertEquals(publicKey, publicPoint.toPublicKey())
        val bigR = presign(signers)

        val message = "Signer Test"
        val hash = SHA256().digest(message.toByteArray())

        val partialSignatures = partialSignMessage(signers, hash)

        val ecdsaSignature= combinePartialSignatures(bigR, partialSignatures, publicPoint, hash)

        assertTrue(ecdsaSignature.verifySecp256k1(hash, publicKey), "failed to convert and verified ecdsa signature")
    }

    @Test
    fun testSignerFails() {
        // Wrong orders
        val n = 5 // Number of total parties.
        val t = 3 // Threshold of minimum required signers.

        val ssid = generateSessionId()
        val parties = mutableMapOf<Int, Signer>()
        val partyIds = parties.keys.toList()
        for (i in 1..n) {
            parties[i] = Signer(
                id = i,
                ssid = ssid,
                threshold = t,
            )
        }

        // Calling round 2/3 before round1
        assertFails {
            parties[2]!!.keygenRound2(partyIds)
        }

        assertFails {
            val round2Broadcast = mutableMapOf<Int, Map<Int, KeygenRound2Broadcast>>()
            val round1Broadcast = mutableMapOf<Int, Map<Int, KeygenRound1Broadcast>>()
            parties[3]!!.keygenRound3(partyIds, round1Broadcast, round2Broadcast)
        }

        assertFails {
            val round2Broadcast = mutableMapOf<Int, Map<Int, KeygenRound2Broadcast>>()
            val round3Broadcast = mutableMapOf<Int, Map<Int, KeygenRound3Broadcast>>()
            parties[3]!!.keygenOutput(partyIds, round2Broadcast, round3Broadcast)
        }

        assertFails {
            parties[5]!!.auxRound2(partyIds)
        }

        assertFails {
            val round2Broadcast = mutableMapOf<Int, Map<Int, AuxRound2Broadcast>>()
            val round1Broadcast = mutableMapOf<Int, Map<Int, AuxRound1Broadcast>>()
            parties[3]!!.auxRound3(partyIds, round1Broadcast, round2Broadcast)
        }

        assertFails {
            val round2Broadcast = mutableMapOf<Int, Map<Int, AuxRound2Broadcast>>()
            val round3Broadcast = mutableMapOf<Int, Map<Int, AuxRound3Broadcast>>()
            parties[3]!!.auxOutput(partyIds, round2Broadcast, round3Broadcast)
        }

        assertFails {
            val round1Broadcast = mutableMapOf<Int, Map<Int, PresignRound1Broadcast>>()
            parties[1]!!.presignRound2(partyIds, round1Broadcast)
        }

        assertFails {
            val round2Broadcast = mutableMapOf<Int, Map<Int, PresignRound2Broadcast>>()
            parties[3]!!.presignRound3(partyIds, round2Broadcast)
        }

        assertFails {
            val round3Broadcast = mutableMapOf<Int, Map<Int, PresignRound3Broadcast>>()
            parties[3]!!.presignOutput(partyIds, round3Broadcast)
        }

        // Starting presign without key generation/aux
        assertFails {
            presign(parties)
        }
    }


    private fun keygen(parties : Map<Int, Signer>) {
        val partyIds = parties.keys.toList()
        // KEYGEN ROUND 1
        val keygenRound1AllBroadcasts = mutableMapOf<Int, Map<Int, KeygenRound1Broadcast>>()
        for (i in partyIds) {
            keygenRound1AllBroadcasts[i] = parties[i]!!.keygenRound1(partyIds)
        }

        // KEYGEN ROUND 2
        val keygenRound2AllBroadcasts = mutableMapOf<Int, Map<Int, KeygenRound2Broadcast>>()
        for (i in partyIds) {
            keygenRound2AllBroadcasts[i] = parties[i]!!.keygenRound2(partyIds)
        }

        // KEYGEN ROUND 3
        val keygenRound3AllBroadcasts = mutableMapOf<Int, Map<Int, KeygenRound3Broadcast>>()
        for (i in partyIds) {
            keygenRound3AllBroadcasts[i] = parties[i]!!.keygenRound3(partyIds, keygenRound1AllBroadcasts, keygenRound2AllBroadcasts)
        }

        // KEYGEN OUTPUT
        val publicPoints = mutableMapOf<Int, Point>()
        for (i in partyIds) {
            publicPoints[i] = parties[i]!!.keygenOutput(partyIds, keygenRound2AllBroadcasts, keygenRound3AllBroadcasts)
        }

        // Check all public Points
        val publicPoint = publicPoints[partyIds[0]]!!
        for (i in partyIds) {
            assertEquals(publicPoints[i], publicPoint)
        }
    }

    private fun aux(parties: Map<Int, Signer>) : Map<Int, PublicPrecomputation> {
        val partyIds = parties.keys.toList()

        // AUX ROUND 1
        val auxRound1AllBroadcasts = mutableMapOf<Int, Map<Int, AuxRound1Broadcast>>()
        for (i in partyIds) {
            auxRound1AllBroadcasts[i] = parties[i]!!.auxRound1(partyIds)
        }

        // AUX ROUND 2
        val auxRound2AllBroadcasts = mutableMapOf<Int, Map<Int, AuxRound2Broadcast>>()
        for (i in partyIds) {
            auxRound2AllBroadcasts[i] = parties[i]!!.auxRound2(partyIds)
        }

        // AUX ROUND 3
        val auxRound3AllBroadcasts = mutableMapOf<Int, Map<Int, AuxRound3Broadcast>>()
        for (i in partyIds) {
            auxRound3AllBroadcasts[i] = parties[i]!!.auxRound3(partyIds, auxRound1AllBroadcasts, auxRound2AllBroadcasts)
        }

        // AUX OUTPUT
        val publicPrecomps = mutableMapOf<Int, Map<Int, PublicPrecomputation>>()
        for (i in partyIds) {
            publicPrecomps[i] = parties[i]!!.auxOutput(partyIds, auxRound2AllBroadcasts, auxRound3AllBroadcasts)
        }

        // Check all public Points
        val publicPrecomp = publicPrecomps[partyIds[0]]!!
        for (i in partyIds) {
            for (j in partyIds) {
                assertEquals(publicPrecomps[i]!![j]!!, publicPrecomp[j])
            }
        }

        return publicPrecomp
    }



    private fun presign(signers: Map<Int, Signer>) : Point {
        val signerIds = signers.keys.toList()

        // PRESIGN ROUND 1
        val presignRound1AllBroadcasts = mutableMapOf<Int, Map<Int, PresignRound1Broadcast>>()
        for (i in signerIds) {
            presignRound1AllBroadcasts[i] = signers[i]!!.presignRound1(signerIds)
        }

        // PRESIGN ROUND 2
        val presignRound2AllBroadcasts = mutableMapOf<Int, Map<Int, PresignRound2Broadcast>>()
        for (i in signerIds) {
            presignRound2AllBroadcasts[i] = signers[i]!!.presignRound2(signerIds, presignRound1AllBroadcasts)
        }

        // PRESIGN ROUND 3
        val presignRound3AllBroadcasts = mutableMapOf<Int, Map<Int, PresignRound3Broadcast>>()
        for (i in signerIds) {
            presignRound3AllBroadcasts[i] = signers[i]!!.presignRound3(signerIds, presignRound2AllBroadcasts)
        }

        // PRESIGN OUTPUT
        val bigRs = mutableMapOf<Int, Point>()
        for (i in signerIds) {
            bigRs[i] = signers[i]!!.presignOutput(signerIds, presignRound3AllBroadcasts)
        }

        // VERIFY OUTPUT CONSISTENCY
        val referenceBigR = bigRs[signerIds[0]]!!
        for (i in signerIds) {
            assertEquals(referenceBigR, bigRs[i])
        }

        return referenceBigR
    }

    private fun partialSignMessage(signers: Map<Int, Signer>, hash: ByteArray) : List<PartialSignature> {
        val partialSignatures = mutableListOf<PartialSignature>()

        for (i in signers.keys.toList()) {
            partialSignatures.add(signers[i]!!.partialSignMessage(hash))
        }

        return partialSignatures
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
            assertEquals(publicPoints[i], referencePoint)
        }

        return referencePoint to referencePrecomp
    }
}