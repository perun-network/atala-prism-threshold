package zk

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.ecdsa.secp256k1Order
import perun_network.ecdsa_threshold.math.sampleL
import perun_network.ecdsa_threshold.math.sampleLPrime
import perun_network.ecdsa_threshold.math.sampleScalar
import perun_network.ecdsa_threshold.paillier.*
import perun_network.ecdsa_threshold.pedersen.PedersenParameters
import perun_network.ecdsa_threshold.zero_knowledge.affg.AffgPrivate
import perun_network.ecdsa_threshold.zero_knowledge.affg.AffgProof
import perun_network.ecdsa_threshold.zero_knowledge.affg.AffgPublic
import perun_network.ecdsa_threshold.zero_knowledge.affg.produceAffGMaterials
import java.math.BigInteger
import kotlin.test.assertEquals

class AffgTest {
    @Test
    fun testAffg() {
        ZK.initialize()
        val verifierPaillier = ZK.verifierPaillierPublic
        val verifierPedersen = ZK.pedersenParams
        val prover = ZK.proverPaillierPublic

        val c = BigInteger.valueOf(12)
        val (C, _) = verifierPaillier.encryptRandom(c)

        val x = sampleL()
        val X = Scalar(x.mod(secp256k1Order())).actOnBase()

        val y = sampleLPrime()
        val (Y, rhoY) = prover.encryptRandom(y)

        val Cx = C.clone().modPowNSquared(verifierPaillier, x)
        val (Dtmp, rho) = verifierPaillier.encryptRandom(y)
        val D = Dtmp.modMulNSquared(verifierPaillier, Cx)

        val affgPublic = AffgPublic(
            C,
            D,
            Y,
            X,
            verifierPaillier,
            prover,
            verifierPedersen
        )

        val affgPrivate = AffgPrivate(
            x,
            y,
            rho,
            rhoY
        )

        val affgProof = AffgProof.newProof(0, affgPublic, affgPrivate)
        assertTrue(affgProof.verify(0, affgPublic))
    }

    @Test
    fun testProduceAffgMaterials() {
        ZK.initialize()
        val paillierI = ZK.proverPaillierPublic
        val paillierJ = ZK.verifierPaillierPublic

        val skI = ZK.proverPaillierSecret
        val skJ = ZK.verifierPaillierSecret

        val aI = sampleScalar()
        val aJ = sampleScalar()

        val bI = sampleScalar()
        val bJ = sampleScalar()

        val (BI, _) = paillierI.encryptRandom(bI.value)
        val (BJ, _) = paillierJ.encryptRandom(bJ.value)

        val aibj = aI.multiply(bJ)
        val ajbi = aJ.multiply(bI)
        val c = aibj.add(ajbi)

        val AI = aI.actOnBase()
        val AJ = aJ.actOnBase()

        val (betaI, DI, FI, proofI) = produceAffGMaterials(0, aI.value, AI, BJ, skI, paillierJ, ZK.pedersenParams)
        val (betaJ, DJ, FJ, proofJ) = produceAffGMaterials(1, aJ.value, AJ, BI, skJ, paillierI, ZK.pedersenParams)

        assertTrue(proofI.verify(0, AffgPublic(BJ, DI, FI, AI, paillierJ, paillierI, ZK.pedersenParams)))
        assertTrue(proofJ.verify(1, AffgPublic(BI, DJ, FJ, AJ, paillierI, paillierJ, ZK.pedersenParams)))

        val alphaI = skI.decrypt(DJ)
        val alphaJ = skJ.decrypt(DI)
        val gammaI = alphaI.add(betaI).mod(secp256k1Order())
        val gammaJ = alphaJ.add(betaJ).mod(secp256k1Order())

        val gamma = gammaI.add(gammaJ).mod(secp256k1Order())
        val gammaS = Scalar(gamma.mod(secp256k1Order()))

        assertEquals(c, gammaS, "a•b should be equal to α + β")
    }


    @Test
    fun testAffgFails() {
        @Test
        fun `test affg proof fails with invalid parameters`() {
            // Mocked invalid Paillier public and secret keys
            val (paillierPublic, paillierSecret) =  paillierKeyGenMock()

            // Mocked invalid Pedersen parameters
            val pedersenParametersInvalid = PedersenParameters(
                BigInteger("17"), // Arbitrary invalid values
                BigInteger("23"),
                BigInteger("100")
            )

            // Random invalid values for ciphertexts (not valid Paillier encrypted values)
            val invalidCipherText = PaillierCipherText(BigInteger("999999999999999"))

            // Mocked invalid elliptic curve point not on secp256k1 curve
            val invalidPoint = Point(BigInteger("999999999"), BigInteger("123456789"))

            // Construct public parameters with invalid data
            val affgPublicInvalid = AffgPublic(
                C = invalidCipherText,
                D = invalidCipherText,
                Y = invalidCipherText,
                X = invalidPoint, // Invalid point
                n0 = paillierPublic,
                n1 = paillierPublic,
                aux = pedersenParametersInvalid
            )

            // Create invalid private parameters
            val affgPrivateInvalid = AffgPrivate(
                x = BigInteger("999999999"),
                y = BigInteger("123456789"),
                rho = BigInteger("222222222"),
                rhoY = BigInteger("333333333")
            )

            // Create invalid proof based on invalid parameters
            val affgProofInvalid = AffgProof.newProof(42, affgPublicInvalid, affgPrivateInvalid)

            // Verifying the proof should fail
            val isProofValid = affgProofInvalid.verify(42, affgPublicInvalid)

            // Assert that the proof validation returns false, meaning the proof fails
            assertFalse(isProofValid)
        }
    }
}