package perun_network.ecdsa_threshold.zkproof

import com.ionspin.kotlin.bignum.integer.Quadruple
import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.math.intervalLPrime
import perun_network.ecdsa_threshold.paillier.PaillierCipherText
import perun_network.ecdsa_threshold.paillier.PaillierPublic
import perun_network.ecdsa_threshold.paillier.PaillierSecret
import perun_network.ecdsa_threshold.pedersen.PedersenParameters
import perun_network.ecdsa_threshold.zkproof.affg.AffgPrivate
import perun_network.ecdsa_threshold.zkproof.affg.AffgProof
import perun_network.ecdsa_threshold.zkproof.affg.AffgPublic
import java.math.BigInteger

data class Quintuple<A, B, C, D, E>(val first: A, val second: B, val third: C, val fourth: D, val fifth: E)

fun newMta(
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
    val BetaNeg = intervalLPrime()

    val (F, R) = sender.publicKey.enc(BetaNeg) // F = encᵢ(-β, r)

    val (D, S) = receiver.enc(BetaNeg)
    val tmp = receiverEncryptedShare.clone().mul(receiver, senderSecretShare) // tmp = aᵢ ⊙ Bⱼ
    D.add(receiver, tmp) // D = encⱼ(-β;s) ⊕ (aᵢ ⊙ Bⱼ) = encⱼ(aᵢ•bⱼ-β)

    return Quintuple(D, F, S, R, BetaNeg)
}


fun proveAffG(
    h: Hash,
    senderSecretShare: BigInteger, // senderSecretShare = aᵢ
    senderSecretSharePoint: Point, // senderSecretSharePoint = Aᵢ = aᵢ⋅G
    receiverEncryptedShare: PaillierCipherText, // receiverEncryptedShare = Encⱼ(bⱼ)
    sender: PaillierSecret,
    receiver: PaillierPublic,
    verifier: PedersenParameters
): Quadruple<
        BigInteger, // Beta = β
        PaillierCipherText, // D = (aⱼ ⊙ Bᵢ) ⊕ encᵢ(- β, s)
        PaillierCipherText, // F = encⱼ(-β, r)
        AffgProof   // Proof = zkaffg proof of correct encryption.
        > {
    val (D, F, S, R, BetaNeg) = newMta(senderSecretShare, receiverEncryptedShare, sender, receiver)
    val proof = AffgProof.newProof(h, AffgPublic(
        kv = receiverEncryptedShare,
        dv = D,
        fp = F,
        xp = senderSecretSharePoint,
        prover = sender.publicKey,
        verifier = receiver,
        aux = verifier
    ), AffgPrivate(
        X = senderSecretShare,
        Y = BetaNeg,
        S = S,
        R = R
    )
    )
    val Beta = BetaNeg.negate()
    return Quadruple(Beta, D, F, proof)
}
