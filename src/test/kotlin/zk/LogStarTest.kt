package zk

import org.junit.jupiter.api.Assertions.assertTrue
import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.ecdsa.secp256k1Order
import perun_network.ecdsa_threshold.math.sampleL
import perun_network.ecdsa_threshold.math.sampleScalar
import perun_network.ecdsa_threshold.zkproof.logstar.LogStarPrivate
import perun_network.ecdsa_threshold.zkproof.logstar.LogStarProof
import perun_network.ecdsa_threshold.zkproof.logstar.LogStarPublic
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
}