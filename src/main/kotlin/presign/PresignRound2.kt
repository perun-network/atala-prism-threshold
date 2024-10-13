package perun_network.ecdsa_threshold.presign

import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.ecdsa.newBasePoint
import perun_network.ecdsa_threshold.keygen.PublicPrecomputation
import perun_network.ecdsa_threshold.paillier.PaillierCipherText
import perun_network.ecdsa_threshold.paillier.PaillierSecret
import perun_network.ecdsa_threshold.zkproof.affg.AffgProof
import perun_network.ecdsa_threshold.zkproof.affg.produceAffGMaterials
import perun_network.ecdsa_threshold.zkproof.enc.EncPublic
import perun_network.ecdsa_threshold.zkproof.logstar.LogStarPrivate
import perun_network.ecdsa_threshold.zkproof.logstar.LogStarProof
import perun_network.ecdsa_threshold.zkproof.logstar.LogStarPublic

import java.math.BigInteger

/**
 * Represents the output of the second round of the presigning process.
 *
 * @property ssid A unique identifier for the session.
 * @property id The identifier of the signer.
 * @property bigGammaShare The computed big gamma share for the signer.
 * @property deltaD The Paillier ciphertext representing Delta D.
 * @property deltaF The Paillier ciphertext representing Delta F.
 * @property deltaProof The proof associated with delta.
 * @property chiD The Paillier ciphertext representing Chi D.
 * @property chiF The Paillier ciphertext representing Chi F.
 * @property chiProof The proof associated with chi.
 * @property proofLog The log-star proof associated with the presigning process.
 * @property chiBeta The beta value for chi.
 * @property deltaBeta The beta value for delta.
 */
class PresignRound2Output (
    val ssid: ByteArray,
    val id : Int,
    val bigGammaShare : Point,
    val deltaD: PaillierCipherText,
    val deltaF: PaillierCipherText,
    val deltaProof: AffgProof,
    val chiD: PaillierCipherText,
    val chiF: PaillierCipherText,
    val chiProof: AffgProof,
    val proofLog: LogStarProof,
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
 * @property publics A map of public precomputed values indexed by signer identifiers.
 */
class PresignRound2Input (
    val ssid: ByteArray,
    val id: Int,
    val gammaShare: Scalar,
    val secretECDSA: Scalar,
    val secretPaillier : PaillierSecret,
    val gNonce: BigInteger,
    val publics: Map<Int, PublicPrecomputation>
) {
    /**
     * Produces the output for the second round of the presigning process.
     *
     * This method generates necessary ciphertexts and proofs for each signer.
     *
     * @param signers A list of signer identifiers participating in the presigning.
     * @param ks A map of Paillier ciphertexts indexed by signer identifiers.
     * @param gs A map of Paillier ciphertexts indexed by signer identifiers.
     * @param ecdsas A map of ECDSA points indexed by signer identifiers.
     * @return A pair containing a map of the presign outputs for each signer and the computed big gamma share.
     */
    fun producePresignRound2Output(
        signers : List<Int>,
        ks : Map<Int, PaillierCipherText>,
        gs : Map<Int, PaillierCipherText>,
        ecdsas : Map<Int, Point>,
    ): Pair<Map<Int, PresignRound2Output>, Point> {
        val result = mutableMapOf<Int, PresignRound2Output>()
        // Γᵢ = [γᵢ]⋅G
        val bigGammaShare = gammaShare.actOnBase()

        for (j in signers) {
            if (j != id) {
                // deltaBeta = βi,j
                // compute DeltaD = Dᵢⱼ
                // compute DeltaF = Fᵢⱼ
                // compute deltaProof = ψj,i
                val (deltaBeta, deltaD, deltaF, deltaProof) = produceAffGMaterials(id, gammaShare.value, bigGammaShare, ks[j]!!.clone(), secretPaillier, publics[j]!!.paillierPublic, publics[j]!!.aux)
                // chiBeta = β^i,j
                // compute chiD = D^ᵢⱼ
                // compute chiF = F^ᵢⱼ
                // compute chiProof = ψ^j,i
                val (chiBeta, chiD, chiF, chiProof) = produceAffGMaterials(id, secretECDSA.value, ecdsas[id]!!, ks[j]!!.clone(), secretPaillier, publics[j]!!.paillierPublic, publics[j]!!.aux)

                val proofLog = LogStarProof.newProof(id,
                    LogStarPublic(gs[id]!!, bigGammaShare, newBasePoint(),  publics[id]!!.paillierPublic, publics[j]!!.aux),
                    LogStarPrivate(gammaShare.value, gNonce))

                val presignOutput2 = PresignRound2Output(
                    ssid = ssid,
                    id = id,
                    bigGammaShare = bigGammaShare,
                    deltaD = deltaD,
                    deltaF = deltaF,
                    deltaProof = deltaProof,
                    chiD = chiD,
                    chiF = chiF,
                    chiProof = chiProof,
                    proofLog = proofLog,
                    deltaBeta = deltaBeta,
                    chiBeta = chiBeta,
                )
                result[j] = presignOutput2
            }
        }

        return result to bigGammaShare
    }

    /**
     * Verifies the output of the first round of the presigning process from a given signer.
     *
     * @param j The identifier of the signer whose output is being verified.
     * @param presignRound1Output The output from the first round for the given signer.
     * @return True if the verification is successful; otherwise, false.
     */
    fun verifyPresignRound1Output(
        j: Int,
        presignRound1Output : PresignRound1Output,
    ) : Boolean {
        val public = EncPublic(
            K = presignRound1Output.K,
            n0 = publics[j]!!.paillierPublic,
            aux = publics[id]!!.aux,
        )
        return presignRound1Output.proof.verify(presignRound1Output.id, public)
    }
}