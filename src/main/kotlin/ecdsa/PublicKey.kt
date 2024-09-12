package perun_network.ecdsa_threshold.ecdsa

import fr.acinq.secp256k1.Secp256k1

class PublicKey(
    val value : ByteArray
) {
    companion object {
        fun newPublicKey(value: ByteArray): PublicKey {
            if (value.size != 65) {
                throw IllegalArgumentException("Invalid public key length" + value.size)
            }
            return PublicKey(Secp256k1.pubkeyParse(value))
        }
    }
}