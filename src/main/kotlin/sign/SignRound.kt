package perun_network.ecdsa_threshold.sign

import fr.acinq.secp256k1.Secp256k1
import org.kotlincrypto.hash.sha2.SHA256
import perun_network.ecdsa_threshold.ecdsa.*
import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.paillier.PaillierCipherText
import perun_network.ecdsa_threshold.paillier.PaillierPublic
import perun_network.ecdsa_threshold.pedersen.PedersenParameters
import perun_network.ecdsa_threshold.presign.PresignRound3Output
import perun_network.ecdsa_threshold.zkproof.logstar.LogStarProof
import perun_network.ecdsa_threshold.zkproof.logstar.LogStarPublic
import kotlin.reflect.jvm.internal.impl.descriptors.Visibilities.Public

class SignParty(
    val message: ByteArray,
    val ssid: ByteArray,
    val publicKey: PublicKey
) {
    fun createPartialSignature(kShare: ByteArray, chiShare: ByteArray, bigR: Point ): PartialSignature {
        val hash = SHA256().digest(message)
        val rX = bigR.x.toByteArray()
        var sigmaShare = PrivateKey.newPrivateKey(rX).mul(PrivateKey(chiShare)).add(PrivateKey(hash).mul(PrivateKey(kShare)))
        return PartialSignature(
            ssid = ssid,
            sigmarShare = sigmaShare
        )
    }
}

fun partialSining(r : ByteArray, partialSignatures : List<PartialSignature>) : Signature {
    var sigma = PrivateKey.zeroPrivateKey()
    for (partial in partialSignatures) {
        sigma = sigma.add(partial.sigmarShare)
    }

    val signature = Signature(r, sigma.toByteArray())
    return signature
}

fun processPresignOutput(deltaShares: List<Scalar>, bigDeltaShares: List<Point>, gamma: Point) : Point {
    // δ = ∑ⱼ δⱼ
    // Δ = ∑ⱼ Δⱼ
    var delta = Scalar.zero()
    for (deltaShare in deltaShares) {
        delta = delta.add(deltaShare)
    }

    var bigDelta = newBasePoint()
    for (bigDeltaShare in bigDeltaShares) {
        bigDelta = bigDelta.add(bigDeltaShare)
    }

    // Δ == [δ]G
    val deltaComputed = delta.actOnBase().toPublicKey()
    if (deltaComputed.equals(bigDelta)) {
        throw Exception("computed Δ is inconsistent with [δ]G")
    }

    val deltaInv = delta.invert()
    val bigR = scalarMultiply(deltaInv, gamma)

    return bigR
}

fun verifyLogStar(
    proofLog : LogStarProof,
    presignRound3Output: PresignRound3Output,
    k : PaillierCipherText,
    g : PaillierCipherText,
    prover: PaillierPublic,
    pedersen: PedersenParameters,

    ) : Boolean {
    val logStarPublic = LogStarPublic(
        c = k,
        x = presignRound3Output.bigDeltaShare,
        g = presignRound3Output.gamma,
        prover = prover,
        aux = pedersen
    )
    return proofLog.verify(Hash.newHash(), logStarPublic)
}



