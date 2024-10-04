package perun_network.ecdsa_threshold.ecdsa

import fr.acinq.secp256k1.Secp256k1
import java.math.BigInteger

class PartialSignature (
    val ssid : ByteArray,
    val id : Int,
    val sigmaShare: Scalar,
)

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
            return Scalar.zero().toPrivateKey()
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

    fun sign(message: ByteArray): Signature {
        return Signature.fromSecp256k1Signature(Secp256k1.sign(message, this.value))
    }

    fun toScalar() : Scalar  {
        return Scalar(BigInteger(1, value))
    }

    fun toByteArray() : ByteArray {
        return value
    }
}