package perun_network.ecdsa_threshold.sign

import org.kotlincrypto.hash.sha2.SHA256
import perun_network.ecdsa_threshold.ecdsa.*
import perun_network.ecdsa_threshold.keygen.PublicPrecomputation
import perun_network.ecdsa_threshold.paillier.PaillierCipherText
import perun_network.ecdsa_threshold.paillier.PaillierPublic
import perun_network.ecdsa_threshold.pedersen.PedersenParameters
import perun_network.ecdsa_threshold.presign.PresignRound3Output
import perun_network.ecdsa_threshold.zkproof.logstar.LogStarPublic
import java.math.BigInteger

class SignParty(
    val hash: ByteArray,
    val ssid: ByteArray,
    val id : Int,
    val publics: Map<Int, PublicPrecomputation>
) {
    fun createPartialSignature(kShare: Scalar, chiShare: Scalar, bigR: Point ): PartialSignature {
        val rX = bigR.x
        val sigmaShare = Scalar(rX).multiply(chiShare).add(Scalar.scalarFromHash(hash).multiply(kShare))
        return PartialSignature(
            ssid = ssid,
            sigmaShare = sigmaShare.toPrivateKey()
        )
    }

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

fun partialSining(bigR: Point, partialSignatures : List<PartialSignature>) : Signature {
    val r = bigR.x
    var sigma = PrivateKey.zeroPrivateKey()
    for (partial in partialSignatures) {
        sigma = sigma.add(partial.sigmaShare)
    }

    val signature = Signature(r.toByteArray(), sigma.toByteArray())
    return signature
}

fun processPresignOutput(
    signers : List<Int>,
    deltaShares: Map<Int, BigInteger>,
    bigDeltaShares: Map<Int, Point>,
    gamma: Point) : Point {
    // δ = ∑ⱼ δⱼ
    // Δ = ∑ⱼ Δⱼ
    var delta = Scalar.zero()
    var bigDelta = newBasePoint()
    for (i in signers) {
        delta = delta.add(Scalar(deltaShares[i]!!))
        bigDelta = bigDelta.add(bigDeltaShares[i]!!)
    }

    // Δ == [δ]G
    val deltaComputed = delta.actOnBase().toPublicKey()
    if (deltaComputed.equals(bigDelta)) {
        throw Exception("computed Δ is inconsistent with [δ]G")
    }

    // R = Γ^δ−1
    val deltaInv = delta.invert()
    val bigR = scalarMultiply(deltaInv, gamma)

    return bigR
}






