package zk

import perun_network.ecdsa_threshold.math.sampleRID
import perun_network.ecdsa_threshold.paillier.paillierKeyGenMock
import perun_network.ecdsa_threshold.zero_knowledge.FacPrivate
import perun_network.ecdsa_threshold.zero_knowledge.FacProof
import perun_network.ecdsa_threshold.zero_knowledge.FacPublic
import kotlin.test.Test
import kotlin.test.assertTrue

class FacTest {
    @Test
    fun testFacProof() {
            val (aux, _) = paillierKeyGenMock().second.generatePedersenParameters()
            val secretKey = paillierKeyGenMock().second

            val public = FacPublic(
                n = secretKey.publicKey.n,
                aux = aux
            )

            val private = FacPrivate(
                p = secretKey.p,
                q = secretKey.q
            )

            val rid = sampleRID()

            val proof = FacProof.newProof(0, rid, public, private)
            assertTrue(proof.verify(0, rid, public), "Proof verification failed.")
    }
}