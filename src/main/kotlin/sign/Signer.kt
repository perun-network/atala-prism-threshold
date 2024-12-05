package perun_network.ecdsa_threshold.sign

import jdk.jfr.Threshold
import perun_network.ecdsa_threshold.ecdsa.*
import perun_network.ecdsa_threshold.keygen.PublicPrecomputation
import perun_network.ecdsa_threshold.keygen.SecretPrecomputation
import perun_network.ecdsa_threshold.math.shamir.lagrange
import perun_network.ecdsa_threshold.paillier.PaillierCipherText
import perun_network.ecdsa_threshold.sign.aux.Aux
import perun_network.ecdsa_threshold.sign.aux.AuxRound1Broadcast
import perun_network.ecdsa_threshold.sign.aux.AuxRound2Broadcast
import perun_network.ecdsa_threshold.sign.aux.AuxRound3Broadcast
import perun_network.ecdsa_threshold.sign.keygen.Keygen
import perun_network.ecdsa_threshold.sign.keygen.KeygenRound1Broadcast
import perun_network.ecdsa_threshold.sign.keygen.KeygenRound2Broadcast
import perun_network.ecdsa_threshold.sign.keygen.KeygenRound3Broadcast
import perun_network.ecdsa_threshold.sign.presign.*
import java.math.BigInteger

data class ThresholdSigner(
    val id : Int,
    val ssid: ByteArray,
    val threshold : Int,
    private var secretPrecomp : SecretPrecomputation? = null,
    var publicPrecomps: Map<Int, PublicPrecomputation>? = null,

    private var keygen : Keygen? = null,
    private var aux : Aux? = null,
    private var presigner : Presigner? = null,

    // KEYGEN
    var xShare : Scalar? = null,
    var XShares: Map<Int, Point>? = null,

    // PRESIGN
    var elGamalPublics: Map<Int, ElGamalPublic>? = null,

) {

    fun keygenRound1(parties: List<Int>): Map<Int, KeygenRound1Broadcast> {
        if (keygen == null) {
            keygen = Keygen(
                ssid = ssid,
                id = id
            )
        }

        return keygen!!.keygenRound1(parties)
    }

    fun keygenRound2(parties: List<Int>): Map<Int, KeygenRound2Broadcast> {
        if (keygen == null) {
            throw NullPointerException("keygen is not initialized")
        }
        return keygen!!.keygenRound2(parties)
    }

    fun keygenRound3(
        parties: List<Int>,
        keygenRound1Broadcasts: Map<Int, Map<Int, KeygenRound1Broadcast>>,
        keygenRound2Broadcasts: Map<Int, Map<Int, KeygenRound2Broadcast>>
    ): Map<Int, KeygenRound3Broadcast> {
        if (keygen == null) {
            throw NullPointerException("keygen is not initialized")
        }

        val incomingRound1Broadcasts = filterIncomingBroadcast(id, keygenRound1Broadcasts)
        val incomingRound2Broadcasts = filterIncomingBroadcast(id, keygenRound2Broadcasts)

        return keygen!!.keygenRound3(parties, incomingRound1Broadcasts, incomingRound2Broadcasts)
    }

    fun keygenOutput(
        parties: List<Int>,
        keygenRound2Broadcasts: Map<Int, Map<Int, KeygenRound2Broadcast>>,
        keygenRound3Broadcasts: Map<Int, Map<Int, KeygenRound3Broadcast>>
    ) : Point {
        if (keygen == null) {
            throw NullPointerException("keygen is not initialized")
        }

        val incomingRound2Broadcasts = filterIncomingBroadcast(id, keygenRound2Broadcasts)
        val incomingRound3Broadcasts = filterIncomingBroadcast(id, keygenRound3Broadcasts)

        val (xShare, XShares, X) =  keygen!!.keygenOutput(parties,incomingRound2Broadcasts, incomingRound3Broadcasts)
        this.xShare = xShare
        this.XShares = XShares
        return X
    }

    fun auxRound1(parties: List<Int>): Map<Int, AuxRound1Broadcast> {
        if (aux == null) {
            aux = Aux(
                ssid = ssid,
                id = id,
                threshold = threshold,
                previousShare = xShare,
                previousPublic = XShares,
            )
        }

        return aux!!.auxRound1(parties)
    }

    fun auxRound2(parties: List<Int>) : Map<Int, AuxRound2Broadcast> {
        if (aux == null) {
            throw NullPointerException("aux is not initialized")
        }
        return aux!!.auxRound2(parties)
    }



    fun auxRound3(parties: List<Int>,
                  auxRound1Broadcasts : Map<Int, Map<Int, AuxRound1Broadcast>>,
                  auxRound2Broadcasts : Map<Int, Map<Int, AuxRound2Broadcast>>
                  ) : Map<Int, AuxRound3Broadcast> {
        if (aux == null) {
            throw NullPointerException("aux is not initialized")
        }

        val incomingRound1Broadcasts = filterIncomingBroadcast(id, auxRound1Broadcasts)
        val incomingRound2Broadcasts = filterIncomingBroadcast(id, auxRound2Broadcasts)

        return aux!!.auxRound3(parties, incomingRound1Broadcasts, incomingRound2Broadcasts)
    }

    fun auxOutput(
        parties: List<Int>,
        auxRound2Broadcasts: Map<Int, Map<Int, AuxRound2Broadcast>>,
        auxRound3Broadcasts: Map<Int, Map<Int, AuxRound3Broadcast>>) : Map<Int, PublicPrecomputation> {
        if (aux == null) {
            throw NullPointerException("aux is not initialized")
        }

        val incomingRound3Broadcasts = filterIncomingBroadcast(id, auxRound3Broadcasts)
        val incomingRound2Broadcasts = filterIncomingBroadcast(id, auxRound2Broadcasts)

        val auxOutput = aux!!.auxOutput(parties, incomingRound2Broadcasts, incomingRound3Broadcasts)

        this.secretPrecomp = auxOutput.first
        this.publicPrecomps = auxOutput.second
        return this.publicPrecomps!!
    }

    fun scalePrecomputations(signers: List<Int>) : Pair<Map<Int, PublicPrecomputation>, Point> {
        val lagrangeCoefficients = lagrange(signers)
        // Initialize a map to hold the scaled precomputations
        val scaledPrecomps = mutableMapOf<Int, SecretPrecomputation>()
        val scaledPublics = mutableMapOf<Int, PublicPrecomputation>()

        val scaledEcdsaShare = lagrangeCoefficients[id]!!.multiply(this.secretPrecomp!!.ecdsaShare)

        // Scale secret and public ECDSA Shares
        for (id in signers) {
            val scaledPublicShare = lagrangeCoefficients[id]!!.act(publicPrecomps!![id]!!.publicEcdsa)

            scaledPublics[id] = PublicPrecomputation(
                id = id,
                ssid = ssid,
                publicEcdsa = scaledPublicShare,
                paillierPublic = publicPrecomps!![id]!!.paillierPublic,
                aux = publicPrecomps!![id]!!.aux
            )
        }
        // Create a new SecretPrecomputation with the scaled private and public shares
        val scaledSecret = SecretPrecomputation(
            id = id,
            ssid = ssid,
            threshold = threshold,
            ecdsaShare = scaledEcdsaShare,
            paillierSecret = secretPrecomp!!.paillierSecret,
        )

        this.secretPrecomp = scaledSecret
        this.publicPrecomps = scaledPublics

        var public = newPoint()
        for (j in signers) {
            public = public.add(scaledPublics[j]!!.publicEcdsa)
        }

        return scaledPublics to public
    }

    fun presignRound1(signers: List<Int>) : Map<Int, PresignRound1Broadcast> {
        if (presigner == null) {
            presigner = Presigner(
                id = id,
                private = secretPrecomp!!,
                publicPrecomps = publicPrecomps!!
            )
        }

        return presigner!!.presignRound1(signers)
    }

    fun presignRound2(
        parties: List<Int>,
        presignRound1AllBroadcasts : Map<Int, Map<Int, PresignRound1Broadcast>>
    ) : Map<Int, PresignRound2Broadcast> {
        if (presigner == null) {
            throw NullPointerException("presigner is not initialized")
        }

        val incomingPresignRound1Broadcast = filterIncomingBroadcast(id, presignRound1AllBroadcasts)

        val Ks = mutableMapOf<Int, PaillierCipherText>()
        val Gs = mutableMapOf<Int, PaillierCipherText>()
        val elGamalPublics = mutableMapOf<Int, ElGamalPublic>()
        for (j in parties) {
            if (j == id ) {
                Ks [j] = presigner!!.K!!
                Gs[j] = presigner!!.G!!
                elGamalPublics[j] = presigner!!.elGamalPublic!!
            } else {
                Ks[j] = incomingPresignRound1Broadcast[j]!!.K
                Gs[j] = incomingPresignRound1Broadcast[j]!!.G
                elGamalPublics[j] = incomingPresignRound1Broadcast[j]!!.elGamalPublic
            }
        }

        this.elGamalPublics = elGamalPublics

        return presigner!!.presignRound2(parties, Ks, incomingPresignRound1Broadcast)
    }

    fun presignRound3(
        parties: List<Int>,
        presignRound2AllBroadcasts : Map<Int, Map<Int, PresignRound2Broadcast>>
    ) : Map<Int, PresignRound3Broadcast> {
        if (presigner == null) {
            throw NullPointerException("presigner is not initialized")
        }

        val incomingPresignRound2Broadcasts = filterIncomingBroadcast(id, presignRound2AllBroadcasts)

        val bigGammaShares = mutableMapOf<Int,  Point>()
        for ( j in parties ) {
            if (j == id) {
                bigGammaShares[j] = presigner!!.bigGammaShare!!
            } else {
                bigGammaShares[j] = incomingPresignRound2Broadcasts[j]!!.bigGammaShare
            }
        }

        return presigner!!.presignRound3(parties, bigGammaShares, elGamalPublics!!, incomingPresignRound2Broadcasts)
    }

    fun presignOutput (
        parties: List<Int>,
        presignRound3AllBroadcasts : Map<Int, Map<Int, PresignRound3Broadcast>>
    ) : Point {
        if (presigner == null) {
            throw NullPointerException("presigner is not initialized")
        }

        val incomingPresignRound3Broadcasts = filterIncomingBroadcast(id, presignRound3AllBroadcasts)

        val deltaShares = mutableMapOf<Int,  BigInteger>()
        val bigDeltaShares = mutableMapOf<Int,  Point>()
        for ( j in parties ) {
            if (j == id) {
                deltaShares[j] = presigner!!.deltaShare!!
                bigDeltaShares[j] = presigner!!.bigDeltaShare!!
            } else {
                deltaShares[j] = incomingPresignRound3Broadcasts[j]!!.deltaShare
                bigDeltaShares[j] = incomingPresignRound3Broadcasts[j]!!.bigDeltaShare
            }
        }

        return presigner!!.processPresignOutput(parties, incomingPresignRound3Broadcasts, elGamalPublics!!, deltaShares, bigDeltaShares)
    }

    fun partialSignMessage(
        hash: ByteArray
    ) : PartialSignature {
        if (presigner == null) {
            throw NullPointerException("presigner is not initialized")
        }

        return presigner!!.partialSignMessage(ssid, hash)
    }

    private fun <A : Broadcast> filterIncomingBroadcast(id : Int, broadcasts : Map<Int, Map<Int, A>>) : Map<Int, A> {
        val incomingBroadcasts = mutableMapOf<Int, A>()
        for ((j, broadcast) in broadcasts) {
            if (j != id) {
                incomingBroadcasts[j] = broadcast[id]!!
            }
        }
        return incomingBroadcasts
    }
}

/**
 * Combines partial signatures to create the final ECDSA signature.
 *
 * This function combines all partial signatures from signers to produce the final valid ECDSA signature `(r, s)`.
 * It ensures that the signature is valid with respect to the given public key and message hash.
 *
 * @param bigR The commitment point `R` from the pre-signing process.
 * @param partialSignatures A list of partial signatures from all signers.
 * @param publicPoint The public key point corresponding to the signers.
 * @param hash The hash of the message that was signed.
 * @return A complete ECDSA signature that is valid for the provided message and public key.
 */
fun combinePartialSignatures(bigR: Point, partialSignatures : List<PartialSignature>, publicPoint: Point, hash : ByteArray) : Signature {
    val r = bigR.xScalar()
    var sigma = Scalar.zero()
    for (partial in partialSignatures) {
        sigma = sigma.add(partial.sigmaShare)
    }

    val signature = Signature.newSignature(r, sigma)

    if (!signature.verifyWithPoint(hash, publicPoint)) {
        throw IllegalStateException("invalid signature")
    }

    return signature
}
