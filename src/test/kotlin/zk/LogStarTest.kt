package zk

import org.junit.jupiter.api.Assertions.assertTrue
import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.ecdsa.newPoint
import perun_network.ecdsa_threshold.ecdsa.secp256k1Order
import perun_network.ecdsa_threshold.math.sampleL
import perun_network.ecdsa_threshold.math.sampleScalar
import perun_network.ecdsa_threshold.zero_knowledge.LogStarPrivate
import perun_network.ecdsa_threshold.zero_knowledge.LogStarProof
import perun_network.ecdsa_threshold.zero_knowledge.LogStarPublic
import kotlin.test.Test

class LogStarTest {
    @Test
    fun testLogStar() {
        ZK.initialize()

        val verifier = ZK.pedersenParams
        val prover = ZK.proverPaillierPublic

        val G = sampleScalar().actOnBase()
        val x = sampleL()
        val (C, rho) = prover.encryptRandom(x)
        val X = Scalar(x.mod(secp256k1Order())).act(G)

        val logStarPublic = LogStarPublic(C, X, G, prover, verifier)

        val logStarProof = LogStarProof.newProof(0, logStarPublic, LogStarPrivate(x, rho))
        assertTrue(logStarProof.verify(0, logStarPublic))
    }

    @Test
    fun testLogStar2() {
        ZK.initialize()

        val verifier = ZK.pedersenParams
        val prover = ZK.proverPaillierPublic

        val gammaShares = mutableMapOf<Int, Scalar>()
        for (i in 0 until 5) {
            gammaShares[i] = sampleScalar()
        }

        val bigGammaShares = mutableMapOf<Int, Point>()
        for (i in 0 until 5) {
            bigGammaShares[i] = gammaShares[i]!!.actOnBase()
        }

        var bigGamma = newPoint()
        for ((_, bigGammaShare) in bigGammaShares) {
            bigGamma = bigGamma.add(bigGammaShare)
        }

        val kShare = sampleScalar()
        val (K, kNonce) = prover.encryptRandom(kShare.value)
        val bigDeltaShare = kShare.act(bigGamma)

        val logStarPublic = LogStarPublic(K, bigDeltaShare, bigGamma, prover, verifier)
        val logStarProof = LogStarProof.newProof(100, logStarPublic, LogStarPrivate(kShare.value, kNonce))
        assertTrue(logStarProof.verify(100, logStarPublic))
    }
}