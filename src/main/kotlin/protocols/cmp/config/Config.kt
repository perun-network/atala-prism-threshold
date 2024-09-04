package perun_network.ecdsa_threshold.protocols.cmp.config

import kotlinx.serialization.Serializable
import perun_network.ecdsa_threshold.hash.WriterToWithDomain
import perun_network.ecdsa_threshold.internal.types.RID
import perun_network.ecdsa_threshold.internal.types.ThresholdWrapper
import perun_network.ecdsa_threshold.math.curve.*
import perun_network.ecdsa_threshold.math.polynomial.*
import perun_network.ecdsa_threshold.params.SecBytes
import perun_network.ecdsa_threshold.party.ID
import perun_network.ecdsa_threshold.party.IDSlice
import perun_network.ecdsa_threshold.protocols.cmp.paillier.SecretKey
import java.io.OutputStream
import kotlin.math.min

@Serializable
data class Config (
    // Group returns the Elliptic Curve Group associated with this config.
    var group: Curve,
    var id: ID?,
    var threshold: Int?,
    var ecdsa: Scalar?,
    var elGamal: Scalar?,
    var paillier: SecretKey?,
    var rid: RID?,
    var chainKey: RID?,
    var public: Map<ID, Public>
    ) : WriterToWithDomain {
    fun publicPoint(): Point {
        var sum = group.newPoint()
        val partyIDs = public.keys.toList()
        val l = lagrangeCoefficient(group, partyIDs)
        for ((id, partyJ) in public) {
            sum = sum.add(l[id]!!.act(partyJ.ecdsa))
        }
        return sum
    }

    fun partyIDs(): IDSlice {
        val ids = public.keys.toList()
        return IDSlice(ids)
    }

    override fun writeTo(outputStream: OutputStream): Long {
        var total: Long = 0

        // write threshold
        total += ThresholdWrapper(threshold!!.toUInt()).writeTo(outputStream)

        // write partyIDs
        val partyIDs = partyIDs()
        total += partyIDs.writeTo(outputStream)

        // write rid
        total += rid!!.writeTo(outputStream)


        // write all party data
        for (j in partyIDs) {
            total += public[j]!!.writeTo(outputStream)
        }
        return total
    }

    override fun domain(): String {
        return "CMP Config"
    }

    fun canSign(signers: IDSlice): Boolean {
        if (!validThreshold(threshold!!, signers.size)) return false

        // check for duplicates
        if (!signers.valid()) return false

        if (!signers.contains(id)) return false

        // check that the signers are a subset of the original parties
        for (j in signers) {
            if (public[j] == null) return false
        }

        return true
    }

    fun derive(adjust: Scalar, newChainKey: ByteArray?): Config {
        val chainKey = newChainKey?: chainKey?.toByteArray()
        require(chainKey?.size == SecBytes) { "Expected $SecBytes bytes for chain key, found ${chainKey?.size}" }

        val adjustG = adjust.actOnBase()

        val newPublic = public.mapValues { (k, v) ->
            Public(
                ecdsa = v.ecdsa.add(adjustG),
                elGamal = v.elGamal,
                paillier = v.paillier,
                pedersen = v.pedersen
            )
        }

        return Config(
            group = group,
            id = id,
            threshold = threshold,
            ecdsa = ecdsa?.let { group.newScalar().set(it).add(adjust) },
            elGamal = elGamal,
            paillier = paillier,
            rid = rid,
            chainKey = RID(chainKey!!),
            public = newPublic
        )
    }

}

fun validThreshold(t: Int, n: Int): Boolean {
        return t in 0..min(n - 1, Int.MAX_VALUE)
}
