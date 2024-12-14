package zk

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test
import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.math.sampleL
import perun_network.ecdsa_threshold.math.sampleScalar
import perun_network.ecdsa_threshold.zero_knowledge.EncElgPrivate
import perun_network.ecdsa_threshold.zero_knowledge.EncElgProof
import perun_network.ecdsa_threshold.zero_knowledge.EncElgPublic
import kotlin.test.assertTrue

class EncElgTest {
    @Test
    fun testEncElg() {
        ZK.initialize()
        val prover = ZK.proverPaillierPublic
        val verifier = ZK.pedersenParams

        // Sample x
        val x = sampleL()
        val xScalar = Scalar.scalarFromBigInteger(x)

        // Sample a and b
        val a = sampleScalar()
        val b = sampleScalar()

        // Compute abx = a * b + xScalar
        val abx = a.multiply(b).add(xScalar)

        // Generate points A, B, X
        val A = a.actOnBase()
        val B = b.actOnBase()
        val X = abx.actOnBase()

        val (C, rho) = prover.encryptRandom(x)

        val public = EncElgPublic(
            C = C,
            A = A,
            B = B,
            X = X,
            N0 = prover,
            aux = verifier
        )

        val private =  EncElgPrivate(
            x = x,
            rho = rho,
            a = a,
            b = b
        )

        val proof = EncElgProof.newProof(0, public, private)
        assertTrue(proof.verify(0, public))
    }

    @Test
    fun testEncElgFails() {
        ZK.initialize()
        val prover = ZK.proverPaillierPublic
        val verifier = ZK.pedersenParams

        // Sample x
        val x = sampleL()
        val xScalar = Scalar.scalarFromBigInteger(x)

        // Sample a and b
        val a = sampleScalar()
        val b = sampleScalar()

        // Compute abx = a * b + xScalar
        val abx = a.multiply(b).add(xScalar)

        // Generate points A, B, X
        val A = a.actOnBase()
        val B = b.actOnBase()
        val X = abx.actOnBase()

        val (C, rho) = prover.encryptRandom(x)

        val public = EncElgPublic(
            C = C,
            A = A,
            B = B,
            X = X,
            N0 = prover,
            aux = verifier
        )

        val private =  EncElgPrivate(
            x = x,
            rho = rho,
            a = b,
            b = a
        )

        val proof = EncElgProof.newProof(0, public, private)
        assertFalse(proof.verify(0, public))
    }
}