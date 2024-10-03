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
import kotlin.reflect.jvm.internal.impl.descriptors.Visibilities.Public

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
    val publics: Map<Int, PublicPrecomputation>
) {
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
                val (deltaBeta, deltaD, deltaF, deltaProof) = produceAffGMaterials(id, gammaShare.value, bigGammaShare, ks[j]!!, secretPaillier, publics[j]!!.paillierPublic, publics[j]!!.aux)
                // chiBeta = β^i,j
                // compute chiD = D^ᵢⱼ
                // compute chiF = F^ᵢⱼ
                // compute chiProof = ψ^j,i
                val (chiBeta, chiD, chiF, chiProof) = produceAffGMaterials(id, secretECDSA.value, ecdsas[j]!!, ks[j]!!, secretPaillier, publics[j]!!.paillierPublic, publics[j]!!.aux)

                val proofLog = LogStarProof.newProof(id,
                    LogStarPublic(gs[id]!!, bigGammaShare, newBasePoint(),  publics[id]!!.paillierPublic, publics[id]!!.aux),
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