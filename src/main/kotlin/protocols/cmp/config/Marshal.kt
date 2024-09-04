package perun_network.ecdsa_threshold.protocols.cmp.config

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import perun_network.ecdsa_threshold.internal.types.RID
import perun_network.ecdsa_threshold.math.curve.Point
import perun_network.ecdsa_threshold.math.curve.Scalar
import perun_network.ecdsa_threshold.party.ID
import perun_network.ecdsa_threshold.protocols.cmp.paillier.PublicKey
import perun_network.ecdsa_threshold.protocols.cmp.paillier.PublicKey.Companion.newPublicKey
import perun_network.ecdsa_threshold.protocols.cmp.paillier.PublicKey.Companion.validateN
import perun_network.ecdsa_threshold.protocols.cmp.paillier.newSecretKeyFromPrimes
import perun_network.ecdsa_threshold.protocols.cmp.paillier.validatePrime
import perun_network.ecdsa_threshold.protocols.cmp.pedersen.Parameters
import perun_network.ecdsa_threshold.protocols.cmp.pedersen.Parameters.Companion.validateParameters
import perun_network.ecdsa_threshold.serializers.BigIntegerSerializer
import java.math.BigInteger
import java.security.InvalidKeyException

@Serializable
data class ConfigMarshal(
    val id: ID,
    val threshold: Int,
    val ecdsa: Scalar,
    val elGamal: Scalar,
    @Serializable(with = BigIntegerSerializer::class)
    val p: BigInteger,
    @Serializable(with = BigIntegerSerializer::class)
    val q: BigInteger,
    val rid: RID,
    val chainKey: RID,
    val public: List<PublicMarshal>
)

@Serializable
data class PublicMarshal(
    val id: ID,
    val ecdsa: Point,
    val elGamal: Point,
    @Serializable(with = BigIntegerSerializer::class)
    val n: BigInteger,
    @Serializable(with = BigIntegerSerializer::class)
    val s: BigInteger,
    @Serializable(with = BigIntegerSerializer::class)
    val t: BigInteger?
)

@OptIn(ExperimentalSerializationApi::class)
fun Config.marshalBinary(): ByteArray {
    val cbor = Cbor { }
    val publicList = public.values.map { p ->
        PublicMarshal(
            id = id!!,
            ecdsa = p.ecdsa,
            elGamal = p.elGamal,
            n = p.pedersen!!.n(),
            s = p.pedersen.s(),
            t = p.pedersen.t()
        )
    }
    val configMarshal = ConfigMarshal(
        id = id!!,
        threshold = threshold!!,
        ecdsa = ecdsa!!,
        elGamal = elGamal!!,
        p = paillier!!.p,
        q = paillier!!.q,
        rid = rid!!,
        chainKey = chainKey!!,
        public = publicList
    )
    return cbor.encodeToByteArray(configMarshal)
}

@OptIn(ExperimentalSerializationApi::class)
fun Config.unmarshalBinary(data: ByteArray) {
    val cbor = Cbor { }
    val cm = cbor.decodeFromByteArray<ConfigMarshal>(data)

    // Check ECDSA and ElGamal
    if (cm.ecdsa.isZero() || cm.elGamal.isZero()) {
        throw InvalidKeyException("ECDSA or ElGamal secret key is zero")
    }

    // Validate Paillier primes
    validatePrime(cm.p)
    validatePrime(cm.q)
    val paillierSecret = newSecretKeyFromPrimes(cm.p, cm.q)

    // Handle public parameters
    val publicMap = mutableMapOf<ID, Public>()
    for (pm in cm.public) {
        val p = PublicMarshal(
            id = pm.id,
            ecdsa = pm.ecdsa,
            elGamal = pm.elGamal,
            n = pm.n,
            s = pm.s,
            t = pm.t ?: throw IllegalArgumentException("T is null")
        )

        if (publicMap.containsKey(p.id)) {
            throw IllegalStateException("Duplicate entry for party ${p.id}")
        }

        if (p.id == cm.id) {
            publicMap[p.id] = Public(
                ecdsa = cm.ecdsa.actOnBase(),
                elGamal = cm.elGamal.actOnBase(),
                paillier = paillierSecret.publicKey,
                pedersen = Parameters(paillierSecret.publicKey.modulus(), p.s, p.t!!)
            )
            continue
        }

        var validationException = validateN(p.n)
        if (validationException != null) throw validationException

        validationException = validateParameters(p.n, p.s, p.t)
        if (validationException != null) throw validationException

        if (!p.ecdsa.isIdentity() && !p.elGamal.isIdentity()) {
            val paillierPublic = newPublicKey(p.n)
            publicMap[p.id] = Public(
                ecdsa = p.ecdsa,
                elGamal = p.elGamal,
                paillier = paillierPublic,
                pedersen = Parameters(paillierPublic.modulus(), p.s, p.t!!)
            )
        } else {
            throw IllegalArgumentException("Invalid parameters for party ${p.id}")
        }
    }

    // Verify number of parties w.r.t. threshold
    if (!validThreshold(cm.threshold, publicMap.size)) {
        throw IllegalArgumentException("Threshold ${cm.threshold} is invalid")
    }

    // Check that we are included
    if (!publicMap.containsKey(cm.id)) {
        throw IllegalStateException("No public data for this party")
    }

    this.apply {
        group = this.group
        id = cm.id
        threshold = cm.threshold
        ecdsa = cm.ecdsa
        elGamal = cm.elGamal
        paillier = paillierSecret
        rid = cm.rid
        chainKey = cm.chainKey
        public = publicMap
    }
}