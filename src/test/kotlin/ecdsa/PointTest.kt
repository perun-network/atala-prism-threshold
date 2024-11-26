package ecdsa

import org.junit.jupiter.api.Assertions.assertTrue
import perun_network.ecdsa_threshold.ecdsa.Point
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals

class PointTest {
    private val P = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
    private val A = BigInteger.ZERO
    private val B = BigInteger("7")
    private val G = Point(
        BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16),
        BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
    )

    @Test
    fun testIsOnCurve() {
        assertTrue(G.isOnCurve(), "Generator point should lie on the curve")
        val invalidPoint = Point(G.x, G.y.add(BigInteger.ONE))
        assertTrue(!invalidPoint.isOnCurve(), "Point with modified y-coordinate should not lie on the curve")
    }

    @Test
    fun testInverse() {
        val inverse = G.inverse()
        assertEquals(G.x, inverse.x, "Inverse should have the same x-coordinate")
        assertEquals(perun_network.ecdsa_threshold.ecdsa.P.subtract(G.y).mod(perun_network.ecdsa_threshold.ecdsa.P), inverse.y, "Inverse y-coordinate should be -y mod P")
        val sum = G.add(inverse)
        assertTrue(sum.isIdentity(), "Adding a point to its inverse should result in the identity element")
    }

    @Test
    fun testAddition() {
        val sum = G.add(G)
        assertTrue(sum.isOnCurve(), "Result of point addition should lie on the curve")
        val identity = G.add(Point(BigInteger.ZERO, BigInteger.ZERO))
        assertEquals(G, identity, "Adding the identity element should return the same point")
        val doubleInverse = G.add(G.inverse())
        assertTrue(doubleInverse.isIdentity(), "Adding a point to its inverse should result in the identity element")
    }

    @Test
    fun testIdentity() {
        val identity = Point(BigInteger.ZERO, BigInteger.ZERO)
        assertTrue(identity.isIdentity(), "Point should be the identity element")
        val result = G.add(identity)
        assertEquals(G, result, "Adding the identity element should return the same point")
    }


    @Test
    fun testInvalidPoint() {
        val invalidPoint = Point(G.x, G.y.add(BigInteger.ONE))
        assertTrue(!invalidPoint.isOnCurve(), "Invalid point should not satisfy the curve equation")
    }

    @Test
    fun testDoublingEdgeCase() {
        val edgeCasePoint = Point(G.x, BigInteger.ZERO)
        val result = edgeCasePoint.double()
        assertTrue(result.isIdentity(), "Doubling a point with y=0 should return the identity element")
    }
}