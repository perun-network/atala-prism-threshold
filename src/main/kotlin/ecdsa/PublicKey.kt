package perun_network.ecdsa_threshold.ecdsa

import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
import perun_network.ecdsa_threshold.paillier.PaillierPublic

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

    fun add(other: PublicKey): PublicKey {
        return PublicKey(Secp256k1.pubKeyTweakAdd(value, other.value))
    }

    override fun equals(other: Any?): Boolean {
        return (other is PublicKey) && value.contentEquals(other.value)
    }
}