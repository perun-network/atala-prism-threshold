package zk

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import perun_network.ecdsa_threshold.math.sampleL
import perun_network.ecdsa_threshold.zero_knowledge.enc.EncPrivate
import perun_network.ecdsa_threshold.zero_knowledge.enc.EncProof
import perun_network.ecdsa_threshold.zero_knowledge.enc.EncPublic

class EncTest {
    @Test
    fun testEnc() {
        ZK.initialize()
        val verifier = ZK.pedersenParams
        val prover = ZK.proverPaillierPublic

        // sample k
        val k = sampleL()

        val (K, rho) = prover.encryptRandom(k)
        assertTrue(K == prover.encryptWithNonce(k, rho))

        val encPublic = EncPublic(
            K,
            prover,
            verifier
        )

        val encProof = EncProof.newProof(0, encPublic, EncPrivate(k, rho))
        assertTrue(encProof.verify(0, encPublic))
    }
}