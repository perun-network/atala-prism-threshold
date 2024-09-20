package perun_network.ecdsa_threshold.presign

import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.ecdsa.newBasePoint
import perun_network.ecdsa_threshold.paillier.PaillierCipherText
import perun_network.ecdsa_threshold.paillier.PaillierPublic
import perun_network.ecdsa_threshold.paillier.PaillierSecret
import perun_network.ecdsa_threshold.pedersen.PedersenParameters
import perun_network.ecdsa_threshold.zkproof.affg.AffgProof
import perun_network.ecdsa_threshold.zkproof.enc.EncPublic
import perun_network.ecdsa_threshold.zkproof.logstar.LogStarPrivate
import perun_network.ecdsa_threshold.zkproof.logstar.LogStarProof
import perun_network.ecdsa_threshold.zkproof.logstar.LogStarPublic
import perun_network.ecdsa_threshold.zkproof.produceAffGProof

import java.math.BigInteger

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

class PresignRound2Input (
    val ssid: ByteArray,
    val id: Int,
    val gammaShare: Scalar,
    val secretECDSA: Scalar,
    val secretPaillier : PaillierSecret,
    val gNonce: BigInteger,
    val pailliers : Map<Int, PaillierPublic>,
    val pedersens : Map<Int, PedersenParameters>
) {
    fun producePresignRound2Output(
        kShares : Map<Int, PaillierCipherText>,
        gShares : Map<Int, PaillierCipherText>,
        ecdsas : Map<Int, Point>,
    ): Map<Int, PresignRound2Output> {
        val result = mutableMapOf<Int, PresignRound2Output>()
        // Γᵢ = [γᵢ]⋅G
        val bigGammaShare = gammaShare.actOnBase()

        for (j in pailliers.keys) {
            if (j != id) {
                // deltaBeta = βi,j
                // compute DeltaD = Dᵢⱼ
                // compute DeltaF = Fᵢⱼ
                // compute deltaProof = ψj,i
                val (deltaBeta, deltaD, deltaF, deltaProof) = produceAffGProof(id, gammaShare.value, bigGammaShare, kShares[id]!!, secretPaillier, pailliers[j]!!, pedersens[j]!!)
                // chiBeta = β^i,j
                // compute chiD = D^ᵢⱼ
                // compute chiF = F^ᵢⱼ
                // compute chiProof = ψ^j,i
                val (chiBeta, chiD, chiF, chiProof) = produceAffGProof(id, secretECDSA.value, ecdsas[j]!!, kShares[id]!!, secretPaillier, pailliers[j]!!, pedersens[j]!!)

                val proofLog = LogStarProof.newProof(id,
                    LogStarPublic(gShares[id]!!, bigGammaShare, newBasePoint(),  pailliers[id]!!, pedersens[id]!!),
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

        return result
    }

    fun verifyPresignRound1Output(
        presignRound1Output : PresignRound1Output,
    ) : Boolean {
        val public = EncPublic(
            K = presignRound1Output.K,
            n0 = pailliers[presignRound1Output.id]!!,
            aux = pedersens[id]!!,
        )
        return presignRound1Output.proof.verify(presignRound1Output.id, public)
    }
}