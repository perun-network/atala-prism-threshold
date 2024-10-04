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

        assertTrue(signature.verify(hash, privateKey.publicKey()))
        assertTrue(parsedSignature.verify(hash, privateKey.publicKey()))
    }


    @Test
    fun testCustomSignature() {
        val message = "Hello".toByteArray()
        val hash = SHA256().digest(message)
        val x = sampleScalar()
        val X = x.actOnBase()

        val k = sampleScalar()
        val m = Scalar.scalarFromHash(hash)
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

        val privateKey = x.toPrivateKey()
        val secpSig = Signature(r.toByteArray(), s.toByteArray())
        assertTrue(secpSig.verify(hash, privateKey.publicKey()))
    }

    @Test
    fun testPresignatures() {
        val n = 3
        val message = "Hello".toByteArray()
        val hash = SHA256().digest(message)
        val (public, presigs, R) = newPreSignatures(n)
        val sigmaShares = mutableMapOf<Int, PartialSignature>()
        for ((id, preSignature) in presigs) {
            sigmaShares[id] = preSignature.sign(message)
        }
        for ((_, preSignature) in presigs) {
            val m = Scalar.scalarFromHash(hash)
            val signature = preSignature.signature(sigmaShares)
            val r = R.xScalar()
            val s = Scalar(BigInteger(signature.S))
            assertFalse(r.isZero() || s.isZero())

            val sInv = s.invert()
            val mG = m.actOnBase()
            val rX = r.act(public)
            val R2 = sInv.act(mG.add(rX))
            assertEquals(R2, R)
            assertTrue(signature.verify(hash, public.toPublicKey()))
        }
    }

    fun newPreSignatures(N: Int) : Triple<Point, Map<Int, Presignature>, Point> {
        val sk = sampleScalar()
        val public = sk.actOnBase()
        val k = sampleScalar()
        val kInv = k.invert()
        val R = kInv.actOnBase()
        val chi = sk.multiply(k)

        val kShares = generateShares(k, N)
        val chiShares = generateShares(chi, N)

        val result = mutableMapOf<Int, Presignature>()
        for (i in 0 until N) {
            result[i] = Presignature(
                R = R,
                kShare = kShares[i]!!,
                chiShare = chiShares[i]!!
            )
        }
        return Triple(public, result, R)
    }

    fun generateShares(secret: Scalar, N: Int): Map<Int, Scalar> {
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
    val chiShare: Scalar
) {
    fun sign(message : ByteArray): PartialSignature {
        val m = Scalar.scalarFromHash(message)
        val r = R.xScalar()
        val mk = m.multiply(kShare)
        val rx = r.multiply(chiShare)
        return PartialSignature(
            ssid = message,
            id = 0,
            sigmaShare = mk.add(rx)
        )
    }

    fun signature(sigmaShares: Map<Int, PartialSignature>): Signature {
        var sigma = Scalar.zero()
        for ((_,sigmaShare) in sigmaShares) {
           sigma = sigma.add(sigmaShare.sigmaShare)
        }
        return Signature(R.xScalar().toByteArray(), sigma.toByteArray())
    }
}