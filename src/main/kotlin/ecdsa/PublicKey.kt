package perun_network.ecdsa_threshold.ecdsa

import fr.acinq.secp256k1.Secp256k1

class PublicKey(
    val value : ByteArray
) {
    companion object {
        fun newPublicKey(value: ByteArray): PublicKey {
            return PublicKey(Secp256k1.pubkeyParse(value))
        }
    }
}