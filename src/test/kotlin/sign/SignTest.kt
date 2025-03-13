package sign

import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
import org.junit.jupiter.api.Assertions.assertFalse
import org.kotlincrypto.hash.sha2.SHA256
import perun_network.ecdsa_threshold.ecdsa.*
import perun_network.ecdsa_threshold.math.sampleScalar
import perun_network.ecdsa_threshold.tuple.Sextuple
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
        val (sig, R) = ecdsaSign(x, k, m)

        val r = Scalar.scalarFromByteArray(sig.R)
        val s = Scalar.scalarFromByteArray(sig.S)
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
        val m = Scalar.scalarFromByteArray(hash)
        val (x, X, presigs, k, kShares, chiShares) = newPreSignatures(n)

        val (sig, R) = ecdsaSign(x, k, m)
        assertTrue(sig.verifyWithPoint(hash, X))

        val sig2 = ecdsaPartialsSign(m, n, kShares, chiShares, R)
        assertEquals(Scalar.scalarFromByteArray(sig2.S), Scalar.scalarFromByteArray(sig.S))

        val sigmaShares = mutableMapOf<Int, PartialSignature>()
        for ((id, preSignature) in presigs) {
            assertEquals(R, preSignature.R)
            val partialSig = preSignature.signPartial(hash)
            assertEquals(partialSig.ssid, hash)
            assertEquals(partialSig.id, 0)
            assertEquals(partialSig, PartialSignature.fromByteArray(partialSig.toByteArray()))
            sigmaShares[id] =partialSig
        }
        for ((_, preSignature) in presigs) {
            val signature = preSignature.signature(sigmaShares)
            assertEquals(Scalar.scalarFromByteArray(signature.R), R.xScalar())
            assertEquals(Scalar.scalarFromByteArray(signature.S), Scalar.scalarFromByteArray(sig.S))
            assertTrue(signature.verifyWithPoint(hash, X))
            assertTrue(signature.verifySecp256k1(hash, X.toPublicKey()))
        }
    }

    private fun ecdsaSign(x: Scalar, k: Scalar, m: Scalar): Pair<Signature, Point> {
        val kInv = k.invert()
        val R = kInv.actOnBase()
        val r = R.xScalar()
        val s = (r.multiply(x).add(m)).multiply(k)
        val chi = x.multiply(k)
        val s2 = r.multiply(chi).add(m.multiply(k))
        require(s == s2)
        return Signature.newSignature(r, s) to R
    }

    private fun ecdsaPartialsSign(m:Scalar, N: Int, kShares: Map<Int, Scalar>, chiShares: Map<Int, Scalar>, R: Point): Signature {
        var sigma = Scalar.zero()
        val r = R.xScalar()
        for (i in 0 until N) {
            sigma = sigma.add((m.multiply(kShares[i]!!)).add(r.multiply(chiShares[i]!!)))
        }
        return Signature.newSignature(r, sigma)
    }

    private fun newPreSignatures(N: Int) : Sextuple<Scalar, Point, Map<Int, SimpleShare>, Scalar, Map<Int, Scalar>, Map<Int,Scalar>> {
        val x = sampleScalar()
        val X = x.actOnBase()
        val k = sampleScalar()
        // Ensure k is not zero
        require(k != Scalar.zero()) { "k must not be zero" }

        val kInv = k.invert()
        val R = kInv.actOnBase()

        // Ensure R is not the identity point
        require(!R.isIdentity()) { "R must not be the identity point" }
        val chi = x.multiply(k)

        val kShares = generateShares(k, N)
        val chiShares = generateShares(chi, N)

        val result = mutableMapOf<Int, SimpleShare>()
        for (i in 0 until N) {
            result[i] = SimpleShare(
                R = R,
                kShare = kShares[i]!!,
                chiShare = chiShares[i]!!
            )
        }

        return Sextuple(x, X, result, k, kShares, chiShares)
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

        var total = Scalar.zero()
        for (i in 0 until N) {
            total = total.add(shares[i]!!)
        }
        require(total == secret, { "invalid shares" })
        return shares
    }
}

private data class SimpleShare(
    val R : Point,
    val kShare: Scalar,
    val chiShare: Scalar
) {
    fun signPartial(message : ByteArray): PartialSignature {
        val m = Scalar.scalarFromByteArray(message)
        val r = R.xScalar()
        return PartialSignature(
            ssid = message,
            id = 0,
            sigmaShare = (m.multiply(kShare)).add(r.multiply(chiShare))
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