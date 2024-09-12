package perun_network.ecdsa_threshold.sign

import fr.acinq.secp256k1.Secp256k1
import org.kotlincrypto.hash.sha2.SHA256
import perun_network.ecdsa_threshold.ecdsa.*
import kotlin.reflect.jvm.internal.impl.descriptors.Visibilities.Public

class SignParty(
    val message: ByteArray,
    val ssid: ByteArray,
    val publicKey: PublicKey
) {
    fun createPartialSignature(kShare: ByteArray, chiShare: ByteArray, bigR: ByteArray ): PartialSignature {
        val hash = SHA256().digest(message)
        val rX = xScalar(bigR)
        var sigmaShare = PrivateKey.newPrivateKey(rX).mul(PrivateKey(chiShare)).add(PrivateKey(hash).mul(PrivateKey(rX)))
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
    var delta = Scalar.zero()
    for (deltaShare in deltaShares) {
        delta = delta.add(deltaShare)
    }

    var bigDelta = newBasePoint()
    for (bigDeltaShare in bigDeltaShares) {
        bigDelta = bigDelta.add(bigDeltaShare)
    }

    // Δ == [δ]G
    val deltaComputed = scalarMultiply(delta, newBasePoint()).toPublicKey()
    if (deltaComputed.equals(bigDelta)) {
        throw Exception("computed Δ is inconsistent with [δ]G")
    }

    val deltaInv = delta.invert()
    val bigR = scalarMultiply(deltaInv, gamma)

    return bigR
}





