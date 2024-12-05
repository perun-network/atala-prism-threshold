package zk

import org.junit.jupiter.api.Assertions.*
import perun_network.ecdsa_threshold.math.sampleQuadraticNonResidue
import perun_network.ecdsa_threshold.math.sampleRID
import perun_network.ecdsa_threshold.paillier.paillierKeyGen
import perun_network.ecdsa_threshold.paillier.paillierKeyGenMock
import perun_network.ecdsa_threshold.zero_knowledge.*
import perun_network.ecdsa_threshold.zero_knowledge.fourthRootExponent
import perun_network.ecdsa_threshold.zero_knowledge.makeQuadraticResidue
import java.math.BigInteger
import kotlin.test.Test

class ModTest {
    @Test
    fun testMod() {
        ZK.initialize()
        val zkSecret = ZK.proverPaillierSecret // Initialize with proper Paillier key
        val zkPublic = zkSecret.publicKey
        val public = _root_ide_package_.perun_network.ecdsa_threshold.zero_knowledge.ModPublic(zkPublic.n)
        val private = _root_ide_package_.perun_network.ecdsa_threshold.zero_knowledge.ModPrivate(
            p = zkSecret.p,
            q = zkSecret.q,
            phi = zkSecret.phi
        )

        val rid = sampleRID()

        val proof = _root_ide_package_.perun_network.ecdsa_threshold.zero_knowledge.ModProof.newProof(0, rid, public, private)
        assertTrue(proof.verify(0, rid, public))
    }

    @Test
    fun testSet4thRoot() {
        val p = 311.toBigInteger()

        val q = 331.toBigInteger()

        val pHalf = (p - BigInteger.ONE) / BigInteger.TWO
        val qHalf = (q - BigInteger.ONE) / BigInteger.TWO
        val n = p.multiply(q)
        val phi = (p - BigInteger.ONE) * (q - BigInteger.ONE)
        var y = BigInteger.valueOf(502)
        val w = sampleQuadraticNonResidue(n)

        val nCRT = p.multiply(q)
        val (a, b, x) = makeQuadraticResidue(y, w, pHalf, qHalf, n, p, q)

        val e = _root_ide_package_.perun_network.ecdsa_threshold.zero_knowledge.fourthRootExponent(phi)
        var root = x.modPow(e, nCRT)

        if (b) {
            y = y.multiply(w).mod(n)
        }
        if (a) {
            y = y.negate().mod(n)
        }

        assertNotEquals(BigInteger.ONE, root, "root cannot be 1")
        root = root.modPow(BigInteger.valueOf(4), n)
        assertEquals(y, root, "root^4 should be equal to y")
    }
}