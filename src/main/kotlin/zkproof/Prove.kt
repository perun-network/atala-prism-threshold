package perun_network.ecdsa_threshold.zkproof

import com.ionspin.kotlin.bignum.integer.Quadruple
import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.math.sampleLPrime
import perun_network.ecdsa_threshold.paillier.PaillierCipherText
import perun_network.ecdsa_threshold.paillier.PaillierPublic
import perun_network.ecdsa_threshold.paillier.PaillierSecret
import perun_network.ecdsa_threshold.pedersen.PedersenParameters
import perun_network.ecdsa_threshold.zkproof.affg.AffgPrivate
import perun_network.ecdsa_threshold.zkproof.affg.AffgProof
import perun_network.ecdsa_threshold.zkproof.affg.AffgPublic
import java.math.BigInteger

data class Quintuple<A, B, C, D, E>(val first: A, val second: B, val third: C, val fourth: D, val fifth: E)

fun computeZKMaterials(
    senderSecretShare: BigInteger,
    receiverEncryptedShare: PaillierCipherText,
    sender: PaillierSecret,
    receiver: PaillierPublic
): Quintuple<
        PaillierCipherText,
        PaillierCipherText,
        BigInteger,
        BigInteger,
        BigInteger
        > {
    val y = sampleLPrime()

    val (Y, rhoY) = sender.publicKey.enc(y)

    val (D, rho) = receiver.enc(y)
    val tmp = receiverEncryptedShare.clone().modPowNSquared(receiver, senderSecretShare)
    D.mul(receiver, tmp)

    return Quintuple(D, Y, rho, rhoY, y)
}


fun produceAffGProof(
    id: Int,
    senderSecretShare: BigInteger, // senderSecretShare = aᵢ
    senderSecretSharePoint: Point, // senderSecretSharePoint = Aᵢ = aᵢ⋅G
    receiverEncryptedShare: PaillierCipherText, // receiverEncryptedShare = Encⱼ(bⱼ)
    sender: PaillierSecret,
    receiver: PaillierPublic,
    verifier: PedersenParameters
): Quadruple<
        BigInteger, // beta = β
        PaillierCipherText, // D = (aⱼ ⊙ Bᵢ) ⊕ encᵢ(- β, s)
        PaillierCipherText, // Y = encⱼ(-β, r)
        AffgProof   // Proof = zkaffg proof of correct encryption.
        > {
    val (D, Y, rho, rhoY, y) = computeZKMaterials(senderSecretShare, receiverEncryptedShare, sender, receiver)
    val proof = AffgProof.newProof(
        id,
        AffgPublic(
        C = receiverEncryptedShare,
        D = D,
        Y = Y,
        X = senderSecretSharePoint,
        n0 = sender.publicKey,
        n1 = receiver,
        aux = verifier
    ), AffgPrivate(
        x = senderSecretShare,
        y = y,
        rho = rho,
        rhoY= rhoY
    )
    )
    val beta = y.negate()
    return Quadruple(beta, D, Y, proof)
}
