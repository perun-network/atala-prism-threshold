package zk

import org.junit.jupiter.api.Assertions.assertTrue
import perun_network.ecdsa_threshold.math.sampleScalar
import perun_network.ecdsa_threshold.zero_knowledge.ElogPrivate
import perun_network.ecdsa_threshold.zero_knowledge.ElogProof
import perun_network.ecdsa_threshold.zero_knowledge.ElogPublic
import kotlin.test.Test

class ElogTest {
    @Test
    fun testElog() {
        val H = sampleScalar().actOnBase()
        val X = sampleScalar().actOnBase()
        val y = sampleScalar()
        val Y = y.act(H)

        val lambda = sampleScalar()
        val L = lambda.actOnBase()
        val M  = y.actOnBase().add(lambda.act(X))

        val public = ElogPublic(
            L = L,
            M = M,
            X = X,
            Y = Y,
            h = H
        )

        val private = ElogPrivate(
            y = y,
            lambda = lambda
        )

        val proof = ElogProof.newProof(
            id = 0,
            public = public,
            private = private
        )
        assertTrue(proof.verify(0, public))
    }
}