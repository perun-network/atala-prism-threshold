package zk

import perun_network.ecdsa_threshold.ecdsa.newBasePoint
import perun_network.ecdsa_threshold.math.sampleRID
import perun_network.ecdsa_threshold.math.sampleScalar
import perun_network.ecdsa_threshold.zero_knowledge.sch.SchnorrCommitment
import perun_network.ecdsa_threshold.zero_knowledge.sch.SchnorrPrivate
import perun_network.ecdsa_threshold.zero_knowledge.sch.SchnorrProof
import perun_network.ecdsa_threshold.zero_knowledge.sch.SchnorrPublic
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SchrTest {
    @Test
    fun testSchPass() {

        val schnorrCommitment = SchnorrCommitment.newCommitment()
        val x = sampleScalar()
        val X = x.actOnBase()

        val schnorrPublic = SchnorrPublic(X)
        val schnorrPrivate = SchnorrPrivate(x)

        val rid = sampleRID()
        val proof = SchnorrProof.newProof(0, rid, schnorrPublic, schnorrPrivate)
        assertTrue(proof.verify(0, rid, schnorrPublic), "Proof verification failed")


        val proof2 = SchnorrProof.newProofWithCommitment(0, rid, schnorrPublic, schnorrPrivate, schnorrCommitment)
        assertTrue(proof2.verify(0, rid, schnorrPublic), "Proof with commitment verification failed")
    }

    @Test
    fun testSchFail() {
        val schnorrCommitment = SchnorrCommitment.newCommitment()
        val x = sampleScalar()
        val X = newBasePoint()

        val schnorrPublic = SchnorrPublic(X)
        val schnorrPrivate = SchnorrPrivate(x)

        val rid = sampleRID()
        val proof = SchnorrProof.newProof(0, rid, schnorrPublic, schnorrPrivate)
        assertFalse(proof.verify(0, rid, schnorrPublic),  "Proof should not accept identity point")

        val proof2 = SchnorrProof.newProofWithCommitment(0, rid, schnorrPublic, schnorrPrivate, schnorrCommitment)
        assertFalse(proof2.verify(0, rid, schnorrPublic),  "Proof should not accept identity point")
    }
}