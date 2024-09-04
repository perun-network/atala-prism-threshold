package perun_network.ecdsa_threshold.party

import kotlinx.serialization.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.serializer
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.*
import java.io.*
import java.math.BigInteger
import perun_network.ecdsa_threshold.math.curve.*
import kotlinx.serialization.cbor.Cbor
import perun_network.ecdsa_threshold.hash.WriterToWithDomain

// ID represents a unique identifier for a participant in our scheme.
// It should be a 32-byte string.
@Serializable
data class ID(val id: String) : WriterToWithDomain, Comparable<ID> {
    init {
        require(id.toByteArray().size <= 32) { "ID must be a maximum of 32 bytes" }
    }

    // Scalar converts this ID into a scalar.
    // All of the IDs of our participants form a polynomial sharing of the secret scalar value used for ECDSA.
    fun scalar(group: Curve): Scalar {
        val bytes = id.toByteArray()
        return group.newScalar().setNat(BigInteger(1, bytes))
    }

    // WriteTo writes out the content of this ID, in a domain-separated way.
    @Throws(IOException::class)
    override fun writeTo(w: OutputStream): Long {
        if (id.isEmpty()) {
            throw EOFException("ID is empty")
        }
        val bytes = id.toByteArray()
        w.write(bytes)
        return bytes.size.toLong()
    }

    // Domain separates this type within a hash.Hash.
    override fun domain(): String {
        return "ID"
    }

    override fun compareTo(other: ID): Int {
        return id.compareTo(other.id)
    }

    override fun toString(): String {
        return id
    }
}
// PointMap is a map from party IDs to points.
class PointMap(private val group: Curve, val points: MutableMap<ID, Point> = mutableMapOf()) {

    // NewPointMap creates a PointMap from a map of points.
    constructor(points: Map<ID, Point>) : this(points.values.first().curve(), points.toMutableMap())

    // MarshalBinary serializes the PointMap to bytes using CBOR.
    fun marshalBinary(): ByteArray {
        val pointBytes = points.mapValues { (_, v) -> v.marshalBinary() }
        return Cbor.encodeToByteArray(pointBytes)
    }

    // UnmarshalBinary deserializes the PointMap from bytes using CBOR.
    @Throws(IOException::class)
    fun unmarshalBinary(data: ByteArray) {
        if (group == null) {
            throw IllegalStateException("PointMap.unmarshalBinary called without setting a group")
        }
        val pointBytes: Map<ID, ByteArray> = Cbor.decodeFromByteArray(data)
        points.clear()
        for ((key, value) in pointBytes) {
            val point = group.newPoint()
            point.unmarshalBinary(value)
            points[key] = point
        }
    }
}
