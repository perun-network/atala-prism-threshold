package perun_network.ecdsa_threshold.sign.presign

import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.ecdsa.newBasePoint
import perun_network.ecdsa_threshold.keygen.PublicPrecomputation
import perun_network.ecdsa_threshold.paillier.PaillierCipherText
import perun_network.ecdsa_threshold.paillier.PaillierSecret
import perun_network.ecdsa_threshold.zero_knowledge.elog.ElogPrivate
import perun_network.ecdsa_threshold.zero_knowledge.elog.ElogProof
import perun_network.ecdsa_threshold.zero_knowledge.elog.ElogPublic
import perun_network.ecdsa_threshold.zero_knowledge.enc_elg.EncElgPublic
import perun_network.ecdsa_threshold.zkproof.affg.AffgProof
import perun_network.ecdsa_threshold.zkproof.affg.produceAffGMaterials
import perun_network.ecdsa_threshold.zkproof.enc.EncPublic
import perun_network.ecdsa_threshold.zkproof.logstar.LogStarPrivate
import perun_network.ecdsa_threshold.zkproof.logstar.LogStarProof
import perun_network.ecdsa_threshold.zkproof.logstar.LogStarPublic

import java.math.BigInteger

/**
 * Represents the content of the message that the signer sends to its peer after the second presign round.
 *
 * @property ssid A unique identifier for the session.
 * @property from The identifier of the signer.
 * @property to The identifier of the receiver.
 * @property bigGammaShare The computed big gamma share for the signer.
 * @property deltaD The Paillier ciphertext representing Delta D.
 * @property deltaF The Paillier ciphertext representing Delta F.
 * @property deltaProof The proof associated with delta.
 * @property chiD The Paillier ciphertext representing Chi D.
 * @property chiF The Paillier ciphertext representing Chi F.
 * @property chiProof The proof associated with chi.
 * @property elogProof The log-star proof associated with the presigning process.
 * @property chiBeta The beta value for chi.
 * @property deltaBeta The beta value for delta.
 */
class PresignRound2Broadcast (
    val ssid: ByteArray,
    val from : Int,
    val to: Int,
    val bigGammaShare : Point,
    val deltaD: PaillierCipherText,
    val deltaF: PaillierCipherText,
    val deltaProof: AffgProof,
    val chiD: PaillierCipherText,
    val chiF: PaillierCipherText,
    val chiProof: AffgProof,
    val elogProof: ElogProof,
    val chiBeta: BigInteger,
    val deltaBeta: BigInteger,
)

/**
 * Represents the input for the second round of the presigning process.
 *
 * @property ssid A unique identifier for the session.
 * @property id The identifier of the signer.
 * @property gammaShare The gamma share for the signer.
 * @property secretECDSA The ECDSA secret key for the signer.
 * @property secretPaillier The Paillier secret key for the signer.
 * @property gNonce The nonce used for generating the proof.
 * @property publicPrecomps A map of public precomputed values indexed by signer identifiers.
 */
class PresignRound2Input (
    val ssid: ByteArray,
    val id: Int,
    val gammaShare: Scalar,
    val secretECDSA: Scalar,
    val secretPaillier : PaillierSecret,
    val gNonce: BigInteger,
    val publicPrecomps: Map<Int, PublicPrecomputation>
) {
    /**
     * Produces the output for the second round of the presigning process.
     *
     * This method generates necessary ciphertexts and proofs for each signer.
     *
     * @param signers A list of signer identifiers participating in the presigning.
     * @param ks A map of public Paillier ciphertexts indexed by signer identifiers.
     * @param gs A map of public Paillier ciphertexts indexed by signer identifiers.
     * @return A pair containing a map of the presign outputs for each signer and the computed big gamma share.
     */
    fun producePresignRound2Output(
        signers : List<Int>,
        ks : Map<Int, PaillierCipherText>,
        B1: Point,
        B2: Point,
        Yi: Point,
        bi: Scalar
    ): Pair<Map<Int, PresignRound2Broadcast>, Point> {
        val result = mutableMapOf<Int, PresignRound2Broadcast>()
        // Γᵢ = [γᵢ]⋅G
        val bigGammaShare = gammaShare.actOnBase()

        // ψi = M(prove, Πelog, (epid, i),(Γi, g, Bi,1, Bi,2, Yi); (γi, bi))
        val elogProof = ElogProof.newProof(id,
            ElogPublic(B1, B2, Yi, bigGammaShare, newBasePoint()),
            ElogPrivate(gammaShare, bi)
        )


        for (j in signers) {
            if (j != id) {
                // deltaBeta = βi,j
                // compute DeltaD = Dᵢⱼ
                // compute DeltaF = Fᵢⱼ
                // compute deltaProof = ψj,i
                val (deltaBeta, deltaD, deltaF, deltaProof) = produceAffGMaterials(id, gammaShare.value, bigGammaShare, ks[j]!!.clone(), secretPaillier, publicPrecomps[j]!!.paillierPublic, publicPrecomps[j]!!.aux)
                // chiBeta = β^i,j
                // compute chiD = D^ᵢⱼ
                // compute chiF = F^ᵢⱼ
                // compute chiProof = ψ^j,i
                val (chiBeta, chiD, chiF, chiProof) = produceAffGMaterials(id, secretECDSA.value, publicPrecomps[id]!!.publicEcdsa, ks[j]!!.clone(), secretPaillier, publicPrecomps[j]!!.paillierPublic, publicPrecomps[j]!!.aux)


                val presignOutput2 = PresignRound2Broadcast(
                    ssid = ssid,
                    from = id,
                    to = j,
                    bigGammaShare = bigGammaShare,
                    deltaD = deltaD,
                    deltaF = deltaF,
                    deltaProof = deltaProof,
                    chiD = chiD,
                    chiF = chiF,
                    chiProof = chiProof,
                    elogProof = elogProof,
                    deltaBeta = deltaBeta,
                    chiBeta = chiBeta,
                )
                result[j] = presignOutput2
            }
        }

        return result to bigGammaShare
    }

    /**
     * Verifies the broadcast message of the first round of the presigning process from a given signer.
     *
     * @param j The identifier of the signer whose output is being verified.
     * @param presignRound1Output The output from the first round for the given signer.
     * @return True if the verification is successful; otherwise, false.
     */
    fun verifyPresignRound1Broadcast(
        j: Int,
        presignRound1Broadcast : PresignRound1Broadcast,
    ) : Boolean {
        // Check ssid.
        if (!this.ssid.contentEquals(presignRound1Broadcast.ssid)) {
            throw PresignException("unknown ssid ${presignRound1Broadcast.ssid}")
        }

        // Check identifier.
        if (j == id || presignRound1Broadcast.from != j || id != presignRound1Broadcast.to ) {
            throw PresignException("invalid id from ${presignRound1Broadcast.from} to ${presignRound1Broadcast.to} ")
        }

        // Check enc-elg proof0.
        val public0 = EncElgPublic(
            C = presignRound1Broadcast.K,
            A = presignRound1Broadcast.elGamalPublic.Y,
            B = presignRound1Broadcast.elGamalPublic.A1,
            X = presignRound1Broadcast.elGamalPublic.A2,
            N0 = publicPrecomps[j]!!.paillierPublic,
            aux = publicPrecomps[id]!!.aux,
        )
        if (!presignRound1Broadcast.proof0.verify(presignRound1Broadcast.from, public0)) {
            throw PresignException("failed to validated enc-elg zk proof 0 from ${presignRound1Broadcast.from} to ${presignRound1Broadcast.to}")
        }

        // Check enc-elg proof1
        val public1 = EncElgPublic(
            C = presignRound1Broadcast.G,
            A = presignRound1Broadcast.elGamalPublic.Y,
            B = presignRound1Broadcast.elGamalPublic.B1,
            X = presignRound1Broadcast.elGamalPublic.B2,
            N0 = publicPrecomps[j]!!.paillierPublic,
            aux = publicPrecomps[id]!!.aux,
        )
        if (!presignRound1Broadcast.proof1.verify(presignRound1Broadcast.from, public1)) {
            throw PresignException("failed to validated enc-elg zk proof 1 from ${presignRound1Broadcast.from} to ${presignRound1Broadcast.to}")
        }

        return true
    }
}