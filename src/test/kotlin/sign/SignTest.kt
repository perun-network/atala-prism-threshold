package sign

import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
import org.junit.jupiter.api.Assertions.assertFalse
import org.kotlincrypto.hash.sha2.SHA256
import perun_network.ecdsa_threshold.ecdsa.*
import perun_network.ecdsa_threshold.math.sampleScalar
import java.math.BigInteger
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SignTest {
    @Test
    fun testSignUsingPrivateKey() {
        val privateKeyHex = Hex.decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".lowercase())
        assertTrue(Secp256k1.secKeyVerify(privateKeyHex))
        val privateKey = PrivateKey.newPrivateKey(privateKeyHex)

        // Message to sign
        val message = "Hello, Bitcoin!".toByteArray()
        val hash = SHA256().digest(message)
        val signature = privateKey.sign(hash)
        val parsedSignature = Signature.fromSecp256k1Signature(signature.toSecp256k1Signature())

        assertTrue(signature.verifySecp256k1(hash, privateKey.publicKey()))
        assertTrue(parsedSignature.verifySecp256k1(hash, privateKey.publicKey()))
    }


    @Test
    fun testCustomSignature() {
        val message = "Hello".toByteArray()
        val hash = SHA256().digest(message)
        val x = sampleScalar()
        val X = x.actOnBase()

        val k = sampleScalar()
        val m = Scalar.scalarFromByteArray(hash)
        val kInv = k.invert()
        val R = kInv.actOnBase()
        val r = R.xScalar()
        val s = r.multiply(x).add(m).multiply(k)

        assertFalse(r.isZero() || s.isZero())

        val sInv = s.invert()
        val mG = m.actOnBase()
        val rX = r.act(X)
        val R2 = sInv.act(mG.add(rX))
        assertEquals(R2, R)

        val secpSig = Signature.newSignature(r, s)
        assertTrue(secpSig.verifyWithPoint(hash, X))
        assertTrue(secpSig.verifySecp256k1(hash, X.toPublicKey()))
    }

    @Test
    fun testPresignatures() {
        val n = 5
        val message = "Hello".toByteArray()
        val hash = SHA256().digest(message)
        val (public, presigs) = newPreSignatures(n)
        val sigmaShares = mutableMapOf<Int, PartialSignature>()
        for ((id, preSignature) in presigs) {
            sigmaShares[id] = preSignature.signPartial(message)
        }
        for ((_, preSignature) in presigs) {
            val signature = preSignature.signature(sigmaShares)
            assertTrue(signature.verifyWithPoint(hash, public))
            assertTrue(signature.verifySecp256k1(hash, public.toPublicKey()))
        }
    }

    private fun newPreSignatures(N: Int) : Pair<Point, Map<Int, Presignature>> {
        val x = sampleScalar()
        val xShares = generateShares(x, N)
        val X = x.actOnBase()
        var X2 = newPoint()
        for (i in 0 until N) {
            X2 = X2.add(xShares[i]!!.actOnBase())
        }
        if (X != X2) {
            throw IllegalStateException("Public key not corresponding to Secret")
        }

        val k = sampleScalar()
        // Ensure k is not zero
        require(k != Scalar.zero()) { "k must not be zero" }

        val R = k.actOnBase()

        // Ensure R is not the identity point
        require(!R.isIdentity()) { "R must not be the identity point" }

        val kShares = generateShares(k, N)

        val result = mutableMapOf<Int, Presignature>()
        for (i in 0 until N) {
            result[i] = Presignature(
                R = R,
                kShare = kShares[i]!!,
                xShare = xShares[i]!!
            )
        }
        return X to result
    }

    private fun generateShares(secret: Scalar, N: Int): Map<Int, Scalar> {
        var sum = Scalar.zero()
        val shares = mutableMapOf<Int, Scalar>()

        for (i in 0 until N) {
            if (i == 0) continue // Skip the first ID for later
            val share = sampleScalar()
            sum = sum.add(share)
            shares[i] = share
        }

        // Compute the share for the first party
        shares[0] = secret.subtract(sum)
        if (secret != sum.add(shares[0]!!)) {
            throw Exception("Secret mismatch")
        }
        return shares
    }
}

data class Presignature(
    val R : Point,
    val kShare: Scalar,
    val xShare: Scalar
) {
    fun signPartial(message : ByteArray): PartialSignature {
        val m = Scalar.scalarFromByteArray(message)
        val kShareInv = kShare.invert()
        val r = R.xScalar()
        return PartialSignature(
            ssid = message,
            id = 0,
            sigmaShare = kShareInv.multiply(m.add(r.multiply(xShare)))
        )
    }

    fun signature(sigmaShares: Map<Int, PartialSignature>): Signature {
        var sigma = Scalar.zero()
        for ((_,sigmaShare) in sigmaShares) {
           sigma = sigma.add(sigmaShare.sigmaShare)
        }
        return Signature.newSignature(R.xScalar(), sigma)
    }
}