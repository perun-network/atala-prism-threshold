package zk

import org.junit.jupiter.api.Assertions.assertTrue
import perun_network.ecdsa_threshold.paillier.paillierKeyGenMock
import perun_network.ecdsa_threshold.zero_knowledge.PrmPrivate
import perun_network.ecdsa_threshold.zero_knowledge.PrmProof
import perun_network.ecdsa_threshold.zero_knowledge.PrmPublic
import kotlin.test.Test

class PrmTest {
    @Test
    fun testPrm() {
        val (_, paillierSecret) = paillierKeyGenMock()
        val (aux, lambda) = paillierSecret.generatePedersenParameters()

        val public = PrmPublic(aux)

        val private = PrmPrivate(
            lambda = lambda,
            phi = paillierSecret.phi,
        )

        val proof = PrmProof.newProof(0, public, private)
        assertTrue(proof.verify(0, public))
    }
}