package perun_network.ecdsa_threshold.internal.mta

import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.math.curve.Curve
import perun_network.ecdsa_threshold.math.curve.Point
import perun_network.ecdsa_threshold.math.sample.SecureRandomInputStream
import perun_network.ecdsa_threshold.math.sample.intervalLPrime
import perun_network.ecdsa_threshold.protocols.cmp.paillier.CipherText
import perun_network.ecdsa_threshold.protocols.cmp.paillier.PublicKey
import perun_network.ecdsa_threshold.protocols.cmp.paillier.SecretKey
import perun_network.ecdsa_threshold.protocols.cmp.pedersen.Parameters
import perun_network.ecdsa_threshold.zk.affg.Private
import perun_network.ecdsa_threshold.zk.affg.Proof
import perun_network.ecdsa_threshold.zk.affg.Public
import java.math.BigInteger
import java.security.SecureRandom

data class Quadruple<A, B, C, D>(val first: A, val second: B, val third: C, val fourth: D)

fun proveAffG(
    group: Curve, h: Hash,
    senderSecretShare: BigInteger, senderSecretSharePoint: Point, receiverEncryptedShare: CipherText,
    sender: SecretKey, receiver: PublicKey, verifier: Parameters
): Quadruple<BigInteger, CipherText, CipherText, Proof> {
    val (D, F, S, R, BetaNeg) = newMta(senderSecretShare, receiverEncryptedShare, sender, receiver)
    val proof = Proof.newProof(group, h, Public(
        kv = receiverEncryptedShare,
        dv = D,
        fp = F,
        xp = senderSecretSharePoint,
        prover = sender.publicKey,
        verifier = receiver,
        aux = verifier
    ), Private(
        X = senderSecretShare,
        Y = BetaNeg,
        S = S,
        R = R
    )
    )
    val Beta = BetaNeg.negate()
    return Quadruple(Beta, D, F, proof)
}


fun proveAffP(
    group: Curve, h: Hash,
    senderSecretShare: BigInteger, senderEncryptedShare: CipherText, senderEncryptedShareNonce: BigInteger,
    receiverEncryptedShare: CipherText,
    sender: SecretKey, receiver: PublicKey, verifier: Parameters
): Quadruple<BigInteger, CipherText, CipherText, perun_network.ecdsa_threshold.zk.affp.Proof> {
    val (D, F, S, R, BetaNeg) = newMta(senderSecretShare, receiverEncryptedShare, sender, receiver)
    val proof = perun_network.ecdsa_threshold.zk.affp.Proof.newProof(group, h, perun_network.ecdsa_threshold.zk.affp.Public(
        kv = receiverEncryptedShare,
        dv = D,
        fp = F,
        xp = senderEncryptedShare,
        prover = sender.publicKey,
        verifier = receiver,
        aux = verifier
    ), perun_network.ecdsa_threshold.zk.affp.Private(
        x = senderSecretShare,
        y = BetaNeg,
        s = S,
        rx = senderEncryptedShareNonce,
        r = R
    ))
    val Beta = BetaNeg.negate()
    return Quadruple(Beta, D, F, proof)
}

fun newMta(
    senderSecretShare: BigInteger, receiverEncryptedShare: CipherText,
    sender: SecretKey, receiver: PublicKey
): Quintuple<CipherText, CipherText, BigInteger, BigInteger, BigInteger> {
    val BetaNeg = intervalLPrime(SecureRandomInputStream(SecureRandom()))

    val (F, R) = sender.publicKey.enc(BetaNeg) // F = encᵢ(-β, r)

    val (D, S) = receiver.enc(BetaNeg)
    val tmp = receiverEncryptedShare.clone().mul(receiver, senderSecretShare) // tmp = aᵢ ⊙ Bⱼ
    D.add(receiver, tmp) // D = encⱼ(-β;s) ⊕ (aᵢ ⊙ Bⱼ) = encⱼ(aᵢ•bⱼ-β)

    return Quintuple(D, F, S, R, BetaNeg)
}

data class Quintuple<A, B, C, D, E>(val first: A, val second: B, val third: C, val fourth: D, val fifth: E)