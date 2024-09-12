package perun_network.ecdsa_threshold.ecdsa

import fr.acinq.secp256k1.Secp256k1

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
    }

    fun toSecp256k1Signature(): ByteArray {
        return R + S
    }

    fun verify(message: ByteArray, publicKey: PublicKey): Boolean {
        return Secp256k1.verify(this.toSecp256k1Signature(), message, publicKey.value)
    }
}