package ecdsa

import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.kotlincrypto.hash.sha2.SHA256
import perun_network.ecdsa_threshold.ecdsa.*
import perun_network.ecdsa_threshold.math.sampleScalar
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals

class Secp256k1Test {
    @Test
    fun testBasePubKey() {
        val basePoint = newBasePoint().toPublicKey().value
        val secpBase = Secp256k1.pubkeyParse(basePoint)
        val acinqBase = Secp256k1.pubkeyParse(Hex.decode("0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8".lowercase()))
        assertArrayEquals(secpBase, acinqBase)
    }


    @Test
    fun testPointAddition() {
        val point1 = newBasePoint()
        val point2 = newBasePoint()

        // Expected point addition result from acinq-secp256k1
        val p1 = Secp256k1.pubkeyParse(Hex.decode("0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8".lowercase()))
        val p2 = Secp256k1.pubkeyParse(Hex.decode("0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8".lowercase()))


        val sumAcinq = Secp256k1.pubKeyCombine(arrayOf(p1, p2))

        // Perform point addition using your code
        val sum = point1.add(point2)
        val sumCustom = sum.toPublicKey().value

        // Assert both results are equal
        assertArrayEquals(sumAcinq, sumCustom, "Point addition did not match the secp256k1 library")
    }

    @Test
    fun testActOnPoint() {
        val tweak = Hex.decode("3982F19BEF1615BCCFBB05E321C10E1D4CBA3DF0E841C2E41EEB6016347653C3".lowercase())
        val scalar = Scalar( BigInteger(tweak))
        // Expected scalar multiplication result from acinq-secp256k1
        val base = Hex.decode("0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8".lowercase())


        val resultAcinq = Secp256k1.pubKeyTweakMul(base, scalar.value.toByteArray())

        // Perform scalar multiplication using your code
        val actOnBase = scalar.actOnBase()

        // Assert both results are equal
        assertArrayEquals(resultAcinq, actOnBase.toPublicKey().value, "Scalar multiplication did not match the secp256k1 library")
    }

    @Test
    fun testScalarMultiplication() {
        val tweak = Hex.decode("3982F19BEF1615BCCFBB05E321C10E1D4CBA3DF0E841C2E41EEB6016347653C3".lowercase())
        val scalar = Scalar( BigInteger(tweak))

        // divide into n-shares
        val shares = mutableMapOf<Int, Scalar>()
        var sum = Scalar.zero()
        val N = 5
        for (i in 1 until N) {
            val share = sampleScalar()
            shares[i] = share
            sum = sum.add(share)
        }
        shares[0] = scalar.subtract(sum)

        // Attempts to recreate
        val R1 = scalar.actOnBase()
        var R2 = newPoint()
        for ( i in 0 until N ) {
            R2 = R2.add(shares[i]!!.actOnBase())
        }
        assertEquals(R1.xScalar(), R2.xScalar())

    }

    @Test
    fun testScalarInversion() {
        val tweak = Hex.decode("3982F19BEF1615BCCFBB05E321C10E1D4CBA3DF0E841C2E41EEB6016347653C3".lowercase())
        val scalar = Scalar( BigInteger(tweak))

        // Expected scalar inversion using acinq-secp256k1
        val privateKey = scalar.toPrivateKey().toByteArray()

        // Perform scalar inversion using your code
        val invertedScalar = scalar.invert().invert()
        val resultCustom = invertedScalar.toPrivateKey().toByteArray()

        // Assert both results are equal
        assertArrayEquals(privateKey, resultCustom, "Scalar inversion did not match the secp256k1 library")
    }

    @Test
    fun testSecp256k1ECDSASignature() {
        val privateKeyHex = Hex.decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".lowercase())
        kotlin.test.assertTrue(Secp256k1.secKeyVerify(privateKeyHex))
        val privateKey = PrivateKey.newPrivateKey(privateKeyHex)

        // Message to sign
        val message = "Hello, Bitcoin!".toByteArray()
        val hash = SHA256().digest(message)
        val signature = privateKey.sign(hash)

        // acinqSignature
        val acinqSignature = Secp256k1.sign(hash, privateKeyHex)

        assertArrayEquals(signature.toSecp256k1Signature(), acinqSignature)

        assertTrue(signature.verifySecp256k1(hash, privateKey.publicKey()))
    }
}