package perun_network.ecdsa_threshold.serializers

import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.math.BigInteger

class BigIntegerSerializer : KSerializer<BigInteger> {
    private val delegateSerilizer = ByteArraySerializer()

    override val descriptor: SerialDescriptor = SerialDescriptor("BigInteger", delegateSerilizer.descriptor)

    override fun deserialize(decoder: Decoder): BigInteger {
        val bytes = decoder.decodeSerializableValue(delegateSerilizer)
        return BigInteger(bytes)
    }

    override fun serialize(encoder: Encoder, value: BigInteger) {
        val bytes = value.toByteArray()
        encoder.encodeSerializableValue(delegateSerilizer, bytes)
    }
}