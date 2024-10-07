package perun_network.ecdsa_threshold.ecdsa

import fr.acinq.secp256k1.Secp256k1
import java.math.BigInteger

const val SIGLEN = 64

class Signature (
    val R : ByteArray,
    val S : ByteArray
) {
    companion object {
        fun fromSecp256k1Signature(signature: ByteArray): Signature {
            if (signature.size != SIGLEN) throw IllegalArgumentException("signature's length does not match secp256k1 signature")

            return Signature(
                R = signature.sliceArray(0 until 32),
                S = signature.sliceArray(32 until 64)
            )
        }

        fun newSignature(r: Scalar, s: Scalar): Signature {
            return Signature(
                r.toByteArray(),
                s.toByteArray()
            )
        }
    }

    fun toSecp256k1Signature(): ByteArray {
        val (sig, _) =  Secp256k1.signatureNormalize(R + S)
        return sig
    }

    fun normalize(): Signature {
        var s = Scalar.scalarFromByteArray(S)
        if (s.isHigh()) {
            s = s.normalize()
        }
        return Signature(R, s.toByteArray())
    }

    fun verifySecp256k1(hash: ByteArray, publicKey: PublicKey): Boolean {
        val secpPublic = Secp256k1.pubkeyParse(publicKey.value)
        val secpSignature = this.toSecp256k1Signature()
        return Secp256k1.verify(secpSignature, hash, secpPublic)
    }

    fun verifyWithPoint(hash: ByteArray, publicPoint: Point): Boolean {
        val s = Scalar.scalarFromByteArray(S)
        val r = Scalar.scalarFromByteArray(R)

        if (r.isZero() || s.isZero()) {
            return false
        }

        val m = Scalar.scalarFromByteArray(hash)
        val sInv = s.invert()
        val u1 = sInv.multiply(m)
        val u2 = sInv.multiply(r)
        val u1G = u1.actOnBase()
        val u2X = u2.act(publicPoint)
        val RPrime = u1G.add(u2X)
        val xRPrime = RPrime.xScalar()
        return xRPrime == r
    }
}