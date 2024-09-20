package perun_network.ecdsa_threshold.hash

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.Digest
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.encodeToByteArray
import perun_network.ecdsa_threshold.math.SecBytes
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.SecureRandom
import kotlin.reflect.KClass
import kotlin.reflect.full.findAnnotation

const val DigestLengthBytes = 64 // Assuming params.SecBytes * 2 is 64

class Hash(private val initData: List<Any>, private var digest: Digest<*>?) {
    companion object {
        fun newHash(vararg initialData: Any): Hash {
            return Hash(initialData.toList(), null)
        }

        fun hashWithID(id: Int): Hash {
            val hash = Hash.newHash()
            hash.writeAny(id)
            return hash
        }

    }

    init {
        if (digest == null) {
            val h = Algorithm.Blake3()
            digest = h.createDigest()
        }
        if (initData.isNotEmpty()) {
            digest?.update("CMP-BLAKE".toByteArray())
            for (i in initData.indices) {
                writeAny(initData[i])
            }
        }
    }

    fun digest(): ByteArray {
        return digest!!.digest()
    }

    fun sum(): ByteArray {
        val out = ByteArray(DigestLengthBytes)
        val digestResult = digest!!.digest()
        System.arraycopy(digestResult, 0, out, 0, DigestLengthBytes)
        return out
    }

    fun writeAny(vararg data: Any) {
        for (item in data) {
            when (item) {
                is ByteArray -> writeBytesWithDomain("ByteArray", item)
                is BigInteger -> {
                    val bytes = item.toByteArray()
                    writeBytesWithDomain("BigInteger", bytes)
                }
                is Pair<*, *> -> {
                    val (domain, value) = item
                    if (domain is String && value is ByteArray) {
                        writeBytesWithDomain(domain, value)
                    }
                }
                isSerializableAnnotated(item::class.java) -> {
                    val serializedData = Cbor.encodeToByteArray(item)
                    writeBytesWithDomain(getClassName(item::class), serializedData)
                }
                else -> throw IllegalArgumentException("Invalid type provided as input")
            }
        }
    }

    private fun writeBytesWithDomain(domain: String, bytes: ByteArray) {
        val sizeBuf = ByteBuffer.allocate(4)
        sizeBuf.putInt(domain.length)
        digest?.update(sizeBuf.array())
        digest?.update(domain.toByteArray())

        sizeBuf.clear()
        sizeBuf.putInt(bytes.size)
        digest?.update(sizeBuf.array())
        digest?.update(bytes)
    }

    fun clone(): Hash {
        val copyDigest = digest?.copy()
        return Hash(emptyList(), copyDigest)
    }

    fun fork(data: Any): Hash {
        val newHash = clone()
        newHash.writeAny(data)
        return newHash
    }

    fun commit(vararg data : Any): Pair<Commitment, Decommitment> {
        val secureRandom = SecureRandom()

        val decommitment = Decommitment(ByteArray(SecBytes).apply { secureRandom.nextBytes(this) })

        val h = this.clone() // Assuming Hash has a clone method

        for (item in data) {
            h.writeAny(item) // Assuming writeAny method for writing data
        }

        h.writeAny(decommitment)

        val commitment = Commitment(h.sum() )// Assuming sum method to get commitment

        return Pair(commitment, decommitment)
    }

    fun decommit(commitment: Commitment, decommitment: Decommitment, vararg data: Any): Boolean {
        try {
            if (commitment.validate() != null) return false
            if (!decommitment.validate()) return false

            val h = this.clone() // Assuming Hash has a clone method

            for (item in data) {
                h.writeAny(item) // Assuming writeAny method for writing data
            }

            h.writeAny(decommitment)

            val computedCommitment = h.sum() // Assuming sum method to get commitment

            return commitment.equals(computedCommitment)
        } catch (e: Exception) {
            return false
        }
    }

    private fun isSerializableAnnotated(clazz: Class<*>): Boolean {
        return clazz.kotlin.findAnnotation<Serializable>() != null
    }

    private fun getClassName(kclazz: KClass<*>): String {
        return kclazz.simpleName?: "Unknown"
    }
}

// Constants
const val DIGEST_LENGTH_BYTES = 32 // Set this to your expected digest length

class Commitment(private val bytes : ByteArray) {
    // Validate Commitment
    fun validate(): Exception? {
        if (bytes.size != DIGEST_LENGTH_BYTES) {
            return IllegalArgumentException("commitment: incorrect length (got ${bytes.size}, expected $DIGEST_LENGTH_BYTES)")
        }
        if (bytes.any { it != 0.toByte() }) {
            return null
        }
        return IllegalArgumentException("commitment: commitment is 0")
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Commitment) return false
        return bytes.contentEquals(other.bytes)
    }
}



class Decommitment(private val bytes : ByteArray) {
    // Validate Commitment
    fun validate(): Boolean {
        if (bytes.size != DIGEST_LENGTH_BYTES) {
            throw IllegalArgumentException("decommitment: incorrect length (got ${bytes.size}, expected $DIGEST_LENGTH_BYTES)")
        }
        return bytes.any { it != 0.toByte() }
    }
}