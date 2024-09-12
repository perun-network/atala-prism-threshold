package perun_network.ecdsa_threshold.sign

import perun_network.ecdsa_threshold.ecdsa.PartialSignature
import perun_network.ecdsa_threshold.ecdsa.Signature
import fr.acinq.secp256k1.Secp256k1
import org.kotlincrypto.hash.sha2.SHA256
import perun_network.ecdsa_threshold.ecdsa.PrivateKey
import perun_network.ecdsa_threshold.ecdsa.PublicKey

class SignParty(
    val message: ByteArray,
    val ssid: ByteArray,
    val publicKey: PublicKey
) {
    fun createPartialSignature(kShare: ByteArray, chiShare: ByteArray, r: ByteArray ): PartialSignature {
        val hash = SHA256().digest(message)
        var sigmaShare = PrivateKey.newPrivateKey(r).mul(PrivateKey(chiShare)).add(PrivateKey(hash).mul(PrivateKey(r)))
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




