package perun_network.ecdsa_threshold.ecdsa

import perun_network.ecdsa_threshold.math.curve.Curve
import perun_network.ecdsa_threshold.math.curve.Point
import perun_network.ecdsa_threshold.math.curve.Scalar
import perun_network.ecdsa_threshold.math.curve.fromHash

data class Signature(
    val r : Point,
    var s : Scalar,
) {
    // Companion object to create an empty signature
    companion object {
        // EmptySignature returns a new signature with a given curve, ready to be unmarshalled.
        fun emptySignature(group: Curve): Signature {
            return Signature(r = group.newPoint(), s = group.newScalar())
        }
    }

    // Verify is a custom signature format using curve data.
    fun verify(x: Point, hash: ByteArray): Boolean {
        val group = x.curve()

        val rScalar = r.xScalar()
        if (rScalar!!.isZero() || s.isZero()) {
            return false
        }

        val m = fromHash(group, hash)
        val sInv = group.newScalar().set(s).invert()
        val mG = m.actOnBase()
        val rX = rScalar!!.act(x)
        var r2 = mG.add(rX)
        r2 = sInv.act(r2)
        return r2 == r
    }

    // get a signature in Ethereum format
    fun sigEthereum(): ByteArray? {
        val isOverHalfOrder = s.isOverHalfOrder() // s-values greater than secp256k1n/2 are considered invalid

        if (isOverHalfOrder) {
            s = s.negate()
        }

        val rBytes = r.marshalBinary()
        val sBytes = s.marshalBinary()


        val rs = ByteArray(65)
        System.arraycopy(rBytes, 0, rs, 0, rBytes.size)
        System.arraycopy(sBytes, 0, rs, rBytes.size, sBytes.size)

        val v: Byte = (rBytes[0] - 2).toByte()

        if (isOverHalfOrder) {
            System.arraycopy(rs, 1, rs, 0, rs.size - 1)
            rs[64] = (v.toInt() xor 1).toByte()
        } else {
            System.arraycopy(rs, 1, rs, 0, rs.size - 1)
            rs[64] = v
        }

        rBytes[0] = (rs[64] + 2).toByte()
        r.unmarshalBinary(rBytes)

        return rs
    }
}