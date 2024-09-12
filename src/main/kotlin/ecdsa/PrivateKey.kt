package perun_network.ecdsa_threshold.ecdsa

import fr.acinq.secp256k1.Secp256k1
import perun_network.ecdsa_threshold.secp256k1.Secp256k1Helper
import perun_network.ecdsa_threshold.secp256k1.Secp256k1Lib

class PrivateKey (
    private val value: ByteArray
) {
    companion object {
        fun newPrivateKey(data: ByteArray): PrivateKey {
            if (data.size != 32) {
                throw IllegalArgumentException("data must be 32 bytes")
            }
            if (!Secp256k1.secKeyVerify(data)) {
                throw IllegalArgumentException("invalid private key")
            }
            return PrivateKey(data)
        }

        fun zeroPrivateKey(): PrivateKey {
            return newPrivateKey(ByteArray(32))
        }
    }

    fun add(other: PrivateKey): PrivateKey {
        return PrivateKey(Secp256k1.privKeyTweakAdd(this.value, other.value))
    }

    fun mul(other: PrivateKey): PrivateKey {
        return PrivateKey(Secp256k1.privKeyTweakMul(this.value, other.value))
    }

    fun neg(): PrivateKey {
        return PrivateKey(Secp256k1.privKeyNegate(this.value))
    }

    fun publicKey() : PublicKey {
        return PublicKey(Secp256k1.pubkeyCreate(value))
    }

    fun toByteArray() : ByteArray {
        return value
    }
}