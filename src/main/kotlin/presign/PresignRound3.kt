package perun_network.ecdsa_threshold.presign

import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.ecdsa.newPoint
import perun_network.ecdsa_threshold.ecdsa.secp256k1Order
import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.paillier.PaillierCipherText
import perun_network.ecdsa_threshold.paillier.PaillierPublic
import perun_network.ecdsa_threshold.paillier.PaillierSecret
import perun_network.ecdsa_threshold.pedersen.PedersenParameters
import perun_network.ecdsa_threshold.zkproof.affg.AffgProof
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
    val pailliers: Map<Int, PaillierPublic>,
    val pedersens: Map<Int, PedersenParameters>,
) {
    fun producePresign3Output(
        presignRound2Output: Map<Int, PresignRound2Output>
    ) : Map<Int, PresignRound3Output> {
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

        // Γ = ∑ⱼ Γⱼ
        var gamma = newPoint()
        for (bigGammaShare in bigGammaShares.values) {
            gamma = gamma.add(bigGammaShare)
        }

        // Δᵢ = [kᵢ]Γ
        val bigDeltaShare = kShare.act(gamma)

        // δᵢ = γᵢ kᵢ
        var deltaShare = gammaShare.multiply(kShare.value)

        // χᵢ = xᵢ kᵢ
        var chiShare = secretECDSA.multiply(kShare.value)

        for (i in bigGammaShares.keys) {
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
                    c = kI,
                    x = bigDeltaShare,
                    g = gamma,
                    prover = pailliers[id]!!,
                    aux = pedersens[j]!!,
                )

                val zkPrivate = LogStarPrivate(
                    x= kShare.value,
                    rho= kNonce
                )
                val proofLog = LogStarProof.newProof(Hash.hashWithID(id), logstarPublic, zkPrivate)
                result[j] = PresignRound3Output(
                    ssid = ssid,
                    id = id,
                    chiShare = chiShare,
                    deltaShare = deltaShare,
                    bigDeltaShare = bigDeltaShare,
                    gamma = gamma,
                    proofLog = proofLog
                )
            }
        }

        return result
    }

    fun verifyPresignRound2Output(
        presignRound2Output: PresignRound2Output,
        k : PaillierCipherText,
        g : PaillierCipherText,
        ecdsa: Point,
    ) : Boolean {
        // Verify M(vrfy, Πaff-g_i ,(ssid, j),(Iε,Jε, Di,j , Ki, Fj,i, Γj ), ψi,j ) = 1.
        val deltaPublic = AffgPublic(
            kv = k,
            dv = presignRound2Output.deltaD,
            fp = presignRound2Output.deltaF,
            xp = presignRound2Output.bigGammaShare,
            prover = pailliers[presignRound2Output.id]!!,
            verifier = pailliers[id]!!,
            aux = pedersens[id]!!
        )
        if (!presignRound2Output.deltaProof.verify(Hash.hashWithID(presignRound2Output.id), deltaPublic)) {
            return false
        }

        // Verify M(vrfy, Πaff-g_i,(ssid, j),(Iε,Jε, Dˆk,j , Ki, Fˆj,i, Xj ), ψˆi,j ) = 1
        val chiPublic = AffgPublic(
            kv = k,
            dv = presignRound2Output.chiD,
            fp = presignRound2Output.chiF,
            xp = ecdsa,
            prover = pailliers[presignRound2Output.id]!!,
            verifier = pailliers[id]!!,
            aux = pedersens[id]!!
        )
        if (!presignRound2Output.chiProof.verify(Hash.hashWithID(presignRound2Output.id), chiPublic)) {
            return false
        }

        // Verify M(vrfy, Πlog∗_i,(ssid, j),(Iε, Gj , Γj , g), ψ0, i,j ) = 1
        val logPublic = LogStarPublic(
            c = g,
            x = presignRound2Output.bigGammaShare,
            g = null,
            prover = pailliers[presignRound2Output.id]!!,
            aux = pedersens[id]!!
        )
        return presignRound2Output.proofLog.verify(Hash.hashWithID(presignRound2Output.id), logPublic)
    }

}

