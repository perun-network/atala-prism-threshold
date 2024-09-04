package perun_network.ecdsa_threshold.internal.elgamal

import perun_network.ecdsa_threshold.hash.WriterToWithDomain
import perun_network.ecdsa_threshold.math.curve.Curve
import perun_network.ecdsa_threshold.math.curve.Point
import perun_network.ecdsa_threshold.math.curve.Scalar
import perun_network.ecdsa_threshold.math.sample.SecureRandomInputStream
import perun_network.ecdsa_threshold.math.sample.scalar
import java.io.OutputStream
import java.security.SecureRandom

typealias PublicKey = Point
typealias Nonce = Scalar

class Ciphertext (
    var l: Point,
    var m: Point
) : WriterToWithDomain {
    // Encrypt returns the encryption of `message` as (L=nonce⋅G, M=message⋅G + nonce⋅public), as well as the `nonce`.
    companion object {
        fun encrypt(public: PublicKey, message: Scalar): Pair<Ciphertext, Nonce> {
            val group = public.curve()
            val nonce = scalar(SecureRandomInputStream(SecureRandom()), group)
            val l = nonce.actOnBase()
            val m = message.actOnBase().add(nonce.act(public))
            return Pair(Ciphertext(l, m), nonce)
        }

        // Empty returns a new, empty ciphertext.
        fun empty(group: Curve): Ciphertext {
            return Ciphertext(group.newPoint(), group.newPoint())
        }
    }

    // Valid returns true if the ciphertext passes basic validation.
    fun valid(): Boolean {
        return !(l.isIdentity() || m.isIdentity())
    }

    override fun writeTo(outputStream: OutputStream): Long {
        var total: Long = 0

        val bufL = l.marshalBinary()
        outputStream.write(bufL)
        total += bufL.size

        val bufM = m.marshalBinary()
        outputStream.write(bufM)
        total += bufM.size

        return total
    }

    override fun domain(): String = "ElGamal Ciphertext"

}