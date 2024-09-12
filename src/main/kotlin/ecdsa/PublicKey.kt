package perun_network.ecdsa_threshold.ecdsa

import fr.acinq.secp256k1.Hex
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

        fun newBasePoint() : PublicKey {
            val g = Hex.decode("0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8".lowercase())
            val base = Secp256k1.pubkeyParse(g)
            return PublicKey(base)
        }
    }

    fun add(other: PublicKey): PublicKey {
        return PublicKey(Secp256k1.pubKeyTweakAdd(value, other.value))
    }
}