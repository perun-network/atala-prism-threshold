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
        val sigmaShare = Scalar(rX.mod(secp256k1Order())).multiply(chiShare).add(Scalar.scalarFromHash(hash).multiply(kShare))
        return PartialSignature(
            ssid = ssid,
            id = id,
            sigmaShare = sigmaShare
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

fun partialSigning(bigR: Point, partialSignatures : List<PartialSignature>, publicPoint: Point, hash : ByteArray) : Signature {
    val r = bigR.x.mod(secp256k1Order())
    var sigma = Scalar.zero()
    for (partial in partialSignatures) {
        sigma = sigma.add(partial.sigmaShare)
    }

    val signature = Signature(r.toByteArray(), sigma.toPrivateKey().toByteArray())

    val sInv = sigma.invert()
    val mG = Scalar.scalarFromHash(hash).actOnBase()
    val rX = Scalar(r).act(publicPoint)

    val R2 =  mG.add(rX)
    val bigR2 = sInv.act(R2)
    if  (bigR2 != bigR) {
        throw Exception("invalid signature")
    }

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






