package perun_network.ecdsa_threshold.ecdsa

import fr.acinq.secp256k1.Secp256k1

/**
 * [SIGLEN] is the standard length of ecdsa signature.
 */
const val SIGLEN = 64

/**
 * The `Signature` class represents a cryptographic signature on the secp256k1 elliptic curve,
 * consisting of two components: R and S.
 *
 * @property R The first 32-byte half of the secp256k1 signature.
 * @property S The second 32-byte half of the secp256k1 signature.
 */
class Signature (
    val R : ByteArray,
    val S : ByteArray
) {
    companion object {
        /**
         * Creates a `Signature` instance from a raw 64-byte secp256k1 signature.
         *
         * @param signature The secp256k1 signature, a 64-byte array.
         * @throws IllegalArgumentException if the length of the signature does not match 64 bytes.
         * @return A `Signature` object.
         */
        fun fromSecp256k1Signature(signature: ByteArray): Signature {
            if (signature.size != SIGLEN) throw IllegalArgumentException("signature's length does not match secp256k1 signature")

            return Signature(
                R = signature.sliceArray(0 until 32),
                S = signature.sliceArray(32 until 64)
            )
        }

        /**
         * Creates a new `Signature` instance from two scalar values: r and s.
         *
         * @param r The `r` component of the signature as a `Scalar`.
         * @param s The `s` component of the signature as a `Scalar`.
         * @return A new `Signature` object with the corresponding r and s values.
         */
        fun newSignature(r: Scalar, s: Scalar): Signature {
            return Signature(
                r.toByteArray(),
                s.toByteArray()
            )
        }
    }

    /**
     * Converts this `Signature` object to a normalized secp256k1 64-byte signature.
     *
     * @return A 64-byte normalized signature in secp256k1 format.
     */
    fun toSecp256k1Signature(): ByteArray {
        val (sig, _) =  Secp256k1.signatureNormalize(R + S)
        return sig
    }

    /**
     * Normalizes the `S` value of the signature if it is greater than the curve order divided by 2.
     * This ensures uniqueness by forcing `S` to be low.
     *
     * @return A normalized `Signature` with a potentially updated `S` value.
     */
    fun normalize(): Signature {
        var s = Scalar.scalarFromByteArray(S)
        if (s.isHigh()) {
            s = s.normalize()
        }
        return Signature(R, s.toByteArray())
    }

    /**
     * Verifies the signature using the secp256k1 elliptic curve with the provided message hash and public key.
     *
     * @param hash The 32-byte message hash to verify.
     * @param publicKey The secp256k1 public key to verify the signature against.
     * @return `true` if the signature is valid; `false` otherwise.
     */
    fun verifySecp256k1(hash: ByteArray, publicKey: PublicKey): Boolean {
        val secpPublic = Secp256k1.pubkeyParse(publicKey.value)
        val secpSignature = this.toSecp256k1Signature()
        return Secp256k1.verify(secpSignature, hash, secpPublic)
    }


    /**
     * Verifies the signature using elliptic curve arithmetic based on the provided message hash and public point.
     *
     * @param hash The 32-byte message hash to verify.
     * @param publicPoint The elliptic curve point (public key) used for verification.
     * @return `true` if the signature is valid; `false` otherwise.
     */
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