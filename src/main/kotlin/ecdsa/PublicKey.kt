package perun_network.ecdsa_threshold.ecdsa

import fr.acinq.secp256k1.Secp256k1

/**
 * Represents an ECDSA public key.
 *
 * @property value The byte array representing the public key. It must be 65 bytes long.
 */
class PublicKey(
    val value : ByteArray
) {
    companion object {
        /**
         * Constructs a new [PublicKey] from the provided byte array.
         *
         * @param value The byte array representing the public key. Must be 65 bytes long.
         * @return A [PublicKey] instance.
         * @throws IllegalArgumentException If the public key length is invalid.
         */
        fun newPublicKey(value: ByteArray): PublicKey {
            if (value.size != 65) {
                throw IllegalArgumentException("Invalid public key length" + value.size)
            }
            return PublicKey(Secp256k1.pubkeyParse(value))
        }

    }

    /**
     * Adds another [PublicKey] to this public key using elliptic curve point addition.
     *
     * @param other The public key to add.
     * @return A new [PublicKey] representing the result of the addition.
     */
    fun add(other: PublicKey): PublicKey {
        return PublicKey(Secp256k1.pubKeyTweakAdd(value, other.value))
    }

    /**
     * Checks equality between this [PublicKey] and another object.
     *
     * @param other The object to compare with.
     * @return `true` if the other object is a [PublicKey] with the same byte array, otherwise `false`.
     */
    override fun equals(other: Any?): Boolean {
        return (other is PublicKey) && value.contentEquals(other.value)
    }
}