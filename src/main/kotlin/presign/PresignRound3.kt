package perun_network.ecdsa_threshold.presign

import com.ionspin.kotlin.bignum.integer.Quadruple
import perun_network.ecdsa_threshold.ecdsa.*
import perun_network.ecdsa_threshold.keygen.PublicPrecomputation
import perun_network.ecdsa_threshold.paillier.PaillierCipherText
import perun_network.ecdsa_threshold.paillier.PaillierPublic
import perun_network.ecdsa_threshold.paillier.PaillierSecret
import perun_network.ecdsa_threshold.pedersen.PedersenParameters
import perun_network.ecdsa_threshold.tuple.Quintuple
import perun_network.ecdsa_threshold.zkproof.affg.AffgPublic
import perun_network.ecdsa_threshold.zkproof.logstar.LogStarPrivate
import perun_network.ecdsa_threshold.zkproof.logstar.LogStarProof
import perun_network.ecdsa_threshold.zkproof.logstar.LogStarPublic
import java.math.BigInteger
import kotlin.math.log

data class PresignRound3Output (
    val ssid: ByteArray,
    val id : Int,
    val chiShare : BigInteger,
    val deltaShare : BigInteger,
    val bigDeltaShare : Point,
    val gamma : Point,
    val proofLog: LogStarProof
)

class PresignRound3Input(
    val ssid: ByteArray,
    val id: Int,
    val gammaShare : BigInteger,
    val secretPaillier: PaillierSecret,
    val kShare: Scalar,
    val kI : PaillierCipherText,
    val kNonce: BigInteger,
    val secretECDSA: BigInteger,
    val publics: Map<Int, PublicPrecomputation>
) {
    fun producePresignRound3Output(
        signers : List<Int>,
        selfBigGammaShare : Point,
        presignRound2Output: Map<Int, PresignRound2Output>
    ) : Quintuple<Map<Int, PresignRound3Output>, BigInteger, BigInteger, Point, Point>{
        val  result = mutableMapOf<Int, PresignRound3Output>()
        val bigGammaShares=  mutableMapOf<Int, Point>()
        val deltaShareAlphas= mutableMapOf<Int, BigInteger>() // DeltaShareAlpha[j] = αᵢⱼ
        val deltaShareBetas= mutableMapOf<Int, BigInteger>()  // DeltaShareBeta[j] = βᵢⱼ
        val chiShareAlphas= mutableMapOf<Int, BigInteger>()   // ChiShareAlpha[j] = α̂ᵢⱼ
        val chiShareBetas= mutableMapOf<Int, BigInteger>()   // ChiShareBeta[j] = β̂^ᵢⱼ
        for ((i, output) in presignRound2Output) {
            bigGammaShares[i] = output.bigGammaShare
            deltaShareBetas[i] =  output.deltaBeta
            chiShareBetas[i] = output.chiBeta
            deltaShareAlphas[i] = secretPaillier.decrypt(output.deltaD)
            chiShareAlphas[i] = secretPaillier.decrypt(output.chiD)
        }

        // Add self-values
        bigGammaShares[id] = selfBigGammaShare

        // Γ = ∑ⱼ Γⱼ
        var bigGamma = newPoint()
        for (bigGammaShare in bigGammaShares.values) {
            bigGamma = bigGamma.add(bigGammaShare)
        }

        // Δᵢ = [kᵢ]Γ
        val bigDeltaShare = kShare.act(bigGamma)

        // δᵢ = γᵢ kᵢ
        var deltaShare = gammaShare.multiply(kShare.value)

        // χᵢ = xᵢ kᵢ
        var chiShare = secretECDSA.multiply(kShare.value)

        for (i in signers) {
            if (i != this.id) {
                //δᵢ += αᵢⱼ + βᵢⱼ
                deltaShare = deltaShare.add(deltaShareAlphas[i])
                deltaShare = deltaShare.add(deltaShareBetas[i])

                // χᵢ += α̂ᵢⱼ +  ̂βᵢⱼ
                chiShare = chiShare.add(chiShareAlphas[i])
                chiShare = chiShare.add(chiShareBetas[i])
            }
        }
        deltaShare = deltaShare.mod(secp256k1Order())
        chiShare = chiShare.mod(secp256k1Order())
        for (j in bigGammaShares.keys) {
            if (j != this.id) {
                val logstarPublic = LogStarPublic(
                    C = kI,
                    X = bigDeltaShare,
                    g = bigGamma,
                    n0 = publics[id]!!.paillierPublic,
                    aux = publics[j]!!.aux,
                )

                val zkPrivate = LogStarPrivate(
                    x= kShare.value,
                    rho= kNonce
                )
                val proofLog = LogStarProof.newProof(id, logstarPublic, zkPrivate)
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

    fun verifyPresignRound2Output(
        j : Int,
        presignRound2Output: PresignRound2Output,
        k_i : PaillierCipherText,
        g_j : PaillierCipherText,
        ecdsa_j: Point,
    ) : Boolean {
        // Verify M(vrfy, Πaff-g_i ,(ssid, j),(Iε,Jε, Di,j , Ki, Fj,i, Γj ), ψi,j ) = 1.
        val deltaPublic = AffgPublic(
            C = k_i,
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
            C = k_i,
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
            C = g_j,
            X = presignRound2Output.bigGammaShare,
            g = newBasePoint(),
            n0 = publics[j]!!.paillierPublic,
            aux = publics[id]!!.aux
        )
        return presignRound2Output.proofLog.verify(presignRound2Output.id, logPublic)
    }

}

