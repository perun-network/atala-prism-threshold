package perun_network.ecdsa_threshold.sign

import perun_network.ecdsa_threshold.ecdsa.*
import perun_network.ecdsa_threshold.keygen.PublicPrecomputation
import perun_network.ecdsa_threshold.paillier.PaillierCipherText
import perun_network.ecdsa_threshold.presign.PresignRound3Output
import perun_network.ecdsa_threshold.zkproof.logstar.LogStarPublic
import java.math.BigInteger

/**
 * Represents a signing party in the threshold ECDSA scheme.
 *
 * @property hash The hash of the message to be signed.
 * @property ssid A unique session identifier for the signing process.
 * @property id The unique identifier for the signing party.
 * @property publics A map of public precomputed values indexed by signer identifiers.
 */
class SignParty(
    val hash: ByteArray,
    val ssid: ByteArray,
    val id : Int,
    val publics: Map<Int, PublicPrecomputation>
) {
    /**
     * Creates a partial signature for the signer.
     *
     * @param kShare The scalar value representing the share of the secret key.
     * @param chiShare The share of the signature from the presigning process.
     * @param bigR The point representing the commitment for the signature.
     * @return A [PartialSignature] instance containing the session ID, signer's ID, and the computed signature share.
     */
    fun createPartialSignature(kShare: Scalar, chiShare: Scalar, bigR: Point ): PartialSignature {
        val rX = bigR.xScalar()
        val sigmaShare = rX.multiply(chiShare).add(Scalar.scalarFromByteArray(hash).multiply(kShare))
        return PartialSignature(
            ssid = ssid,
            id = id,
            sigmaShare = sigmaShare
        )
    }

    /**
     * Verifies the output of the third round of the presigning process for a given signer.
     *
     * @param j The identifier of the signer whose output is being verified.
     * @param presignRound3Output The output from the third round for the given signer.
     * @param k_j The Paillier ciphertext for K corresponding to the signer.
     * @return True if the verification is successful; otherwise, false.
     */
    fun verifyPresignRound3Output(
        j : Int,
        presignRound3Output: PresignRound3Output,
        k_j : PaillierCipherText
    ) : Boolean {
        val logStarPublic = LogStarPublic(
            C = k_j,
            X = presignRound3Output.bigDeltaShare,
            g = presignRound3Output.gamma,
            n0 = publics[j]!!.paillierPublic,
            aux = publics[id]!!.aux
        )
        return presignRound3Output.proofLog.verify(presignRound3Output.id, logStarPublic)
    }
}

/**
 * Combines partial signatures into a final signature.
 *
 * @param bigR The point representing the commitment for the signature.
 * @param partialSignatures A list of partial signatures from each signing party.
 * @param publicPoint The public point used for verifying the signature.
 * @param hash The hash of the message that was signed.
 * @return A [Signature] instance representing the final signature.
 * @throws IllegalStateException If the final signature is invalid.
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

/**
 * Processes the presigning outputs from multiple signers to compute the final commitment point.
 *
 * @param signers A list of identifiers for the signers.
 * @param deltaShares A map of delta shares indexed by signer identifiers.
 * @param bigDeltaShares A map of big delta shares indexed by signer identifiers.
 * @param gamma The gamma point from the presigning process.
 * @return The computed point representing the commitment.
 * @throws Exception If the computed point is inconsistent with the expected value.
 */
fun processPresignOutput(
    signers : List<Int>,
    deltaShares: Map<Int, BigInteger>,
    bigDeltaShares: Map<Int, Point>,
    gamma: Point) : Point {
    // δ = ∑ⱼ δⱼ
    // Δ = ∑ⱼ Δⱼ
    var delta = Scalar.zero()
    var bigDelta = newPoint()
    for (i in signers) {
        delta = delta.add(Scalar(deltaShares[i]!!.mod(secp256k1Order())))
        bigDelta = bigDelta.add(bigDeltaShares[i]!!)
    }

    // Δ == [δ]G
    val deltaComputed = delta.actOnBase()
    if (deltaComputed != bigDelta) {
        throw Exception("computed Δ is inconsistent with [δ]G")
    }

    // R = Γ^δ−1
    val deltaInv = delta.invert()
    val bigR = deltaInv.act(gamma)

    return bigR
}