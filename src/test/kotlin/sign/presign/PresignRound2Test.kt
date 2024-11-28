package sign.presign

import perun_network.ecdsa_threshold.math.sampleScalar
import perun_network.ecdsa_threshold.precomp.getSamplePrecomputations
import perun_network.ecdsa_threshold.sign.presign.PresignRound2Input
import kotlin.test.Test
import kotlin.test.assertEquals

class PresignRound2Test {
    @Test
    fun testPresignRound2() {

        val (ids, secretPrecomps, publicPrecomps) = getSamplePrecomputations(2, 1)

        val ssid = secretPrecomps[ids[0]]!!.ssid
        val gammaShare = sampleScalar()
        val (_, gNonce) = publicPrecomps[ids[1]]!!.paillierPublic.encryptRandom(gammaShare.value)

        val secretPaillier = secretPrecomps[ids[0]]!!.paillierSecret

        val presignRound2 = PresignRound2Input(
            ssid = ssid,
            id = ids[0],
            gammaShare = gammaShare,
            secretECDSA = secretPrecomps[ids[0]]!!.ecdsaShare,
            secretPaillier = secretPaillier,
            gNonce = gNonce,
            publicPrecomps = publicPrecomps
        )

        assertEquals(presignRound2.ssid, ssid)
        assertEquals(presignRound2.gammaShare, gammaShare)
        assertEquals(presignRound2.id, ids[0])
        assertEquals(presignRound2.gammaShare, gammaShare)
        assertEquals(presignRound2.publicPrecomps, publicPrecomps)
        assertEquals(presignRound2.secretPaillier, secretPaillier)
        assertEquals(presignRound2.secretECDSA, secretPrecomps[ids[0]]!!.ecdsaShare)
    }
}