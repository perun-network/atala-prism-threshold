package perun_network.ecdsa_threshold.presign

import perun_network.ecdsa_threshold.ecdsa.*
import perun_network.ecdsa_threshold.keygen.PublicPrecomputation
import perun_network.ecdsa_threshold.paillier.PaillierCipherText
import perun_network.ecdsa_threshold.paillier.PaillierSecret
import perun_network.ecdsa_threshold.tuple.Quintuple
import perun_network.ecdsa_threshold.zkproof.affg.AffgPublic
import perun_network.ecdsa_threshold.zkproof.logstar.LogStarPrivate
import perun_network.ecdsa_threshold.zkproof.logstar.LogStarProof
import perun_network.ecdsa_threshold.zkproof.logstar.LogStarPublic
import java.math.BigInteger

/**
 * Represents the output of the third round of the presigning process.
 *
 * @property ssid A unique identifier for the session.
 * @property id The identifier of the signer.
 * @property chiShare The computed chi share for the signer.
 * @property deltaShare The computed delta share for the signer.
 * @property bigDeltaShare The computed big delta share for the signer.
 * @property gamma The computed gamma point for the signer.
 * @property proofLog The log-star proof associated with the presigning process.
 */
data class PresignRound3Output (
    val ssid: ByteArray,
    val id : Int,
    val chiShare : BigInteger,
    val deltaShare : BigInteger,
    val bigDeltaShare : Point,
    val gamma : Point,
    val proofLog: LogStarProof
)

/**
 * Represents the input for the third round of the presigning process.
 *
 * @property ssid A unique identifier for the session.
 * @property id The identifier of the signer.
 * @property gammaShare The gamma share for the signer.
 * @property secretPaillier The Paillier secret key for the signer.
 * @property kShare The scalar value for k.
 * @property K The Paillier ciphertext for K.
 * @property kNonce The nonce used for generating the proof.
 * @property secretECDSA The ECDSA secret key for the signer.
 * @property publics A map of public precomputed values indexed by signer identifiers.
 */
class PresignRound3Input(
    val ssid: ByteArray,
    val id: Int,
    val gammaShare : BigInteger,
    val secretPaillier: PaillierSecret,
    val kShare: Scalar,
    val K : PaillierCipherText,
    val kNonce: BigInteger,
    val secretECDSA: BigInteger,
    val publics: Map<Int, PublicPrecomputation>
) {
    /**
     * Produces the output for the third round of the presigning process.
     *
     * This method generates the necessary shares and proofs for each signer.
     *
     * @param signers A list of signer identifiers participating in the presigning.
     * @param bigGammaShares A map of big gamma shares indexed by signer identifiers.
     * @param presignRound2Outputs A map of outputs from the second round indexed by signer identifiers.
     * @return A quintuple containing a map of the presign outputs for each signer, the computed chi share,
     *         the computed delta share, the computed big delta share, and the computed gamma point.
     */
    fun producePresignRound3Output(
        signers : List<Int>,
        bigGammaShares : Map<Int,Point>,
        presignRound2Outputs: Map<Int, Map<Int, PresignRound2Output>>
    ) : Quintuple<Map<Int, PresignRound3Output>, BigInteger, BigInteger, Point, Point>{
        val  result = mutableMapOf<Int, PresignRound3Output>()
        val deltaShareAlphas= mutableMapOf<Int, BigInteger>() // DeltaShareAlpha[j] = αᵢⱼ
        val deltaShareBetas= mutableMapOf<Int, BigInteger>()  // DeltaShareBeta[j] = βᵢⱼ
        val chiShareAlphas= mutableMapOf<Int, BigInteger>()   // ChiShareAlpha[j] = α̂ᵢⱼ
        val chiShareBetas= mutableMapOf<Int, BigInteger>()   // ChiShareBeta[j] = β̂^ᵢⱼ
        for (j in signers) {
            if (j != id) {
                deltaShareBetas[j] = presignRound2Outputs[j]!![id]!!.deltaBeta
                chiShareBetas[j] = presignRound2Outputs[j]!![id]!!.chiBeta
                deltaShareAlphas[j] = secretPaillier.decrypt(presignRound2Outputs[j]!![id]!!.deltaD)
                chiShareAlphas[j] = secretPaillier.decrypt(presignRound2Outputs[j]!![id]!!.chiD)
            }
        }


        // Γ = ∑ⱼ Γⱼ
        var bigGamma = newPoint()
        for ((_, bigGammaShare) in bigGammaShares) {
            bigGamma = bigGamma.add(bigGammaShare)
        }

        // Δᵢ = [kᵢ]Γ
        val bigDeltaShare = kShare.act(bigGamma)

        // δᵢ = γᵢ kᵢ
        var deltaShare = gammaShare.multiply(kShare.value)

        // χᵢ = xᵢ kᵢ
        var chiShare = secretECDSA.multiply(kShare.value)

        for (j in signers) {
            if (j != this.id) {
                //δᵢ += αᵢⱼ + βᵢⱼ
                deltaShare = deltaShare.add(deltaShareAlphas[j])
                deltaShare = deltaShare.add(deltaShareBetas[j])

                // χᵢ += α̂ᵢⱼ +  ̂βᵢⱼ
                chiShare = chiShare.add(chiShareAlphas[j])
                chiShare = chiShare.add(chiShareBetas[j])
            }
        }
        deltaShare = deltaShare.mod(secp256k1Order())
        chiShare = chiShare.mod(secp256k1Order())
        for (j in signers) {
            if (j != id) {
                val logstarPublic = LogStarPublic(
                    C = K.clone(),
                    X = bigDeltaShare,
                    g = bigGamma,
                    n0 = publics[id]!!.paillierPublic,
                    aux = publics[j]!!.aux,
                )

                val logStarPrivate = LogStarPrivate(
                    x= kShare.value,
                    rho= kNonce
                )
                val proofLog = LogStarProof.newProof(id, logstarPublic, logStarPrivate)
                result[j] = PresignRound3Output(
                    ssid = ssid,
                    id = id,
                    chiShare = chiShare,
                    deltaShare = deltaShare,
                    bigDeltaShare = bigDeltaShare,
                    gamma = bigGamma,
                    proofLog = proofLog
                )
            }
        }

        return Quintuple(result, chiShare, deltaShare, bigDeltaShare, bigGamma)
    }

    /**
     * Verifies the output of the second round of the presigning process for a given signer.
     *
     * @param j The identifier of the signer whose output is being verified.
     * @param presignRound2Output The output from the second round for the given signer.
     * @param k_i The Paillier ciphertext for K.
     * @param g_j The Paillier ciphertext for G.
     * @param ecdsa_j The ECDSA point for the signer.
     * @return True if the verification is successful; otherwise, false.
     */
    fun verifyPresignRound2Output(
        j : Int,
        presignRound2Output: PresignRound2Output,
        k_i : PaillierCipherText,
        g_j : PaillierCipherText,
        ecdsa_j: Point,
    ) : Boolean {
        // Verify M(vrfy, Πaff-g_i ,(ssid, j),(Iε,Jε, Di,j , Ki, Fj,i, Γj ), ψi,j ) = 1.
        val deltaPublic = AffgPublic(
            C = k_i.clone(),
            D = presignRound2Output.deltaD,
            Y = presignRound2Output.deltaF,
            X = presignRound2Output.bigGammaShare,
            n1 = publics[j]!!.paillierPublic,
            n0 = publics[id]!!.paillierPublic,
            aux = publics[id]!!.aux
        )
        if (!presignRound2Output.deltaProof.verify(presignRound2Output.id, deltaPublic)) {
            return false
        }

        // Verify M(vrfy, Πaff-g_i,(ssid, j),(Iε,Jε, Dˆk,j , Ki, Fˆj,i, Xj ), ψˆi,j ) = 1
        val chiPublic = AffgPublic(
            C = k_i.clone(),
            D = presignRound2Output.chiD,
            Y = presignRound2Output.chiF,
            X = ecdsa_j,
            n1 = publics[j]!!.paillierPublic,
            n0= publics[id]!!.paillierPublic,
            aux = publics[id]!!.aux
        )
        if (!presignRound2Output.chiProof.verify(presignRound2Output.id, chiPublic)) {
            return false
        }

        // Verify M(vrfy, Πlog∗_i,(ssid, j),(Iε, Gj , Γj , g), ψ0, i,j ) = 1
        val logPublic = LogStarPublic(
            C = g_j.clone(),
            X = presignRound2Output.bigGammaShare,
            g = newBasePoint(),
            n0 = publics[j]!!.paillierPublic,
            aux = publics[id]!!.aux
        )
        return presignRound2Output.proofLog.verify(presignRound2Output.id, logPublic)
    }

}

