package perun_network.ecdsa_threshold.ecdsa

import fr.acinq.secp256k1.Secp256k1
import kotlinx.serialization.*
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.encoding.*
import kotlinx.serialization.descriptors.*

@Serializable
class PartialSignature(
    val ssid: ByteArray,
    val id: Int,
    @Serializable(with = ScalarSerializer::class) val sigmaShare: Scalar
) {
    @OptIn(ExperimentalSerializationApi::class)
    fun toByteArray(): ByteArray = Cbor.encodeToByteArray(this)

    companion object {
        @OptIn(ExperimentalSerializationApi::class)
        fun fromByteArray(data: ByteArray): PartialSignature = Cbor.decodeFromByteArray(data)
    }
}

// Serializer for Secp256k1Scalar
object ScalarSerializer : KSerializer<Scalar> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Secp256k1Scalar", PrimitiveKind.BYTE)

    override fun serialize(encoder: Encoder, value: Scalar) {
        encoder.encodeSerializableValue(ByteArraySerializer(), value.toByteArray())
    }

    override fun deserialize(decoder: Decoder): Scalar {
        val bytes = decoder.decodeSerializableValue(ByteArraySerializer())
        return Scalar.scalarFromByteArray(bytes)
    }
}

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
}