package perun_network.ecdsa_threshold.ecdsa

import fr.acinq.secp256k1.Secp256k1

/**
 * Represents a partial signature in the ECDSA threshold scheme.
 *
 * @property ssid The session identifier.
 * @property id The ID of the participant.
 * @property sigmaShare The scalar share of the signature.
 */
class PartialSignature (
    val ssid : ByteArray,
    val id : Int,
    val sigmaShare: Scalar,
)

/**
 * Represents an ECDSA private key.
 *
 * @property value The 32-byte private key.
 */
class PrivateKey (
    private val value: ByteArray // must have the size 32-bytes
) {
    companion object {
        /**
         * Constructs a new [PrivateKey] from a 32-byte data array.
         *
         * @param data The private key bytes. Must be 32 bytes long.
         * @throws IllegalArgumentException If the data is not 32 bytes or invalid.
         */
        fun newPrivateKey(data: ByteArray): PrivateKey {
            if (data.size != 32) {
                throw IllegalArgumentException("data must be 32 bytes")
            }
            if (!Secp256k1.secKeyVerify(data)) {
                throw IllegalArgumentException("invalid private key")
            }
            return PrivateKey(data)
        }

        /**
         * Returns a private key that is initialized to zero.
         *
         * @return A zeroed private key.
         */
        fun zeroPrivateKey(): PrivateKey {
            return Scalar.zero().toPrivateKey()
        }
    }

    /**
     * Adds another private key to this private key.
     *
     * @param other The private key to add.
     * @return A new [PrivateKey] representing the result of the addition.
     */
    fun add(other: PrivateKey): PrivateKey {
        return PrivateKey(Secp256k1.privKeyTweakAdd(this.value, other.value))
    }

    /**
     * Multiplies this private key by another private key.
     *
     * @param other The private key to multiply with.
     * @return A new [PrivateKey] representing the result of the multiplication.
     */
    fun mul(other: PrivateKey): PrivateKey {
        return PrivateKey(Secp256k1.privKeyTweakMul(this.value, other.value))
    }

    /**
     * Negates this private key.
     *
     * @return A new [PrivateKey] that is the negation of this private key.
     */
    fun neg(): PrivateKey {
        return PrivateKey(Secp256k1.privKeyNegate(this.value))
    }

    /**
     * Generates the corresponding public key for this private key.
     *
     * @return The [PublicKey] corresponding to this private key.
     */
    fun publicKey() : PublicKey {
        return PublicKey(Secp256k1.pubkeyCreate(value))
    }

    /**
     * Signs a message using this private key.
     *
     * @param message The message to sign.
     * @return The [Signature] of the message.
     */
    fun sign(message: ByteArray): Signature {
        return Signature.fromSecp256k1Signature(Secp256k1.sign(message, this.value))
    }

    /**
     * Converts this private key to a [Scalar].
     *
     * @return The scalar representation of this private key.
     */
    fun toScalar() : Scalar  {
        return Scalar.scalarFromByteArray(value)
    }

    /**
     * Returns the byte array representation of this private key.
     *
     * @return The byte array representing this private key.
     */
    fun toByteArray() : ByteArray {
        return value
    }

    override fun equals(other: Any?): Boolean {
        if (other !is PrivateKey) {
            return false
        }
        return this.value.contentEquals(other.value)
    }

    override fun hashCode(): Int {
        return value.contentHashCode()
    }
}