package perun_network.ecdsa_threshold.party

import perun_network.ecdsa_threshold.hash.WriterToWithDomain
import java.io.IOException
import java.io.OutputStream

data class IDSlice(private val ids: List<ID>) : List<ID> by ids, WriterToWithDomain {
    // NewIDSlice returns a sorted slice from partyIDs.
    companion object {
        fun newIDSlice(partyIDs: List<ID>): IDSlice {
            return IDSlice(partyIDs.sorted())
        }
    }

    // Contains returns true if partyIDs contains id.
    fun contains(vararg idsToCheck: ID): Boolean {
        return idsToCheck.all { search(it) != null }
    }

    // Valid returns true if the IDSlice is sorted and does not contain any duplicates.
    fun valid(): Boolean {
        for (i in 1 until ids.size) {
            if (ids[i - 1] >= ids[i]) {
                return false
            }
        }
        return true
    }


    // Copy returns an identical copy of the received.
    fun copy(): IDSlice {
        return IDSlice(ids.toList())
    }

    // Remove finds id in partyIDs and returns a copy of the slice if it was found.
    fun remove(id: ID): IDSlice {
        return IDSlice(ids.filter { it != id })
    }


    // search returns the index of id or null if not found.
    private fun search(id: ID): Int? {
        val index = ids.binarySearch(id)
        return if (index >= 0) index else null
    }

    // WriteTo writes the full uncompressed point to the output stream.
    override fun writeTo(outputStream: OutputStream): Long {
        if (ids.isEmpty()) {
            throw IOException("Unexpected EOF")
        }

        var totalBytes = 0L
        outputStream.write(ids.size)
        totalBytes += 4 // For the length header

        for (id in ids) {
            val idByteSize = id.writeTo(outputStream)
            totalBytes += idByteSize
        }

        return totalBytes
    }

    override fun domain(): String {
        return "IDSlice"
    }

    // String representation of IDSlice
    override fun toString(): String {
        return ids.joinToString(", ")
    }
}