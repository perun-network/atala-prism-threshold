package perun_network.ecdsa_threshold.protocols.cmp

import perun_network.ecdsa_threshold.ecdsa.PreSignature
import perun_network.ecdsa_threshold.internal.round.Info
import perun_network.ecdsa_threshold.math.curve.Curve
import perun_network.ecdsa_threshold.party.ID
import perun_network.ecdsa_threshold.pool.Pool
import perun_network.ecdsa_threshold.protocol.StartFunc
import perun_network.ecdsa_threshold.protocols.cmp.paillier.keyGen
import perun_network.ecdsa_threshold.protocols.cmp.presign.StartPresign
import perun_network.ecdsa_threshold.protocols.cmp.presign.StartPresignOnline
import perun_network.ecdsa_threshold.protocols.cmp.sign.startSign
import perun_network.ecdsa_threshold.protocols.cmp.keygen.Start as keyGenStart
import perun_network.ecdsa_threshold.protocols.cmp.keygen.Rounds as keyGenRounds

// Keygen generates a new shared ECDSA key over the curve defined by `group`. After a successful execution,
// all participants possess a unique share of this key, as well as auxiliary parameters required during signing.
//
// For better performance, a `Pool` can be provided in order to parallelize certain steps of the protocol.
// Returns a StartFunc if successful.
fun keygen(
    group: Curve,
    selfID: ID,
    participants: List<ID>,
    threshold: Int,
    pool: Pool? = null
): StartFunc {
    val info = Info(
        protocolID = "cmp/keygen-threshold",
        finalRoundNumber = keyGenRounds,
        selfID = selfID,
        partyIDs = participants,
        threshold = threshold,
        group = group
    )
    return keyGenStart(info, pool, null)
}

// Refresh allows the parties to refresh all existing cryptographic keys from a previously generated Config.
// The group's ECDSA public key remains the same, but any previous shares are rendered useless.
// Returns a StartFunc if successful.
fun refresh(
    config: Config,
    pool: Pool? = null
): StartFunc {
    val info = Info(
        protocolID = "cmp/refresh-threshold",
        finalRoundNumber = keyGenRounds,
        selfID = config.id!!,
        partyIDs = config.partyIDs(),
        threshold = config.threshold!!,
        group = config.group
    )
    return keyGenStart(info, pool, config)
}

// Sign generates an ECDSA signature for `messageHash` among the given `signers`.
// Returns a StartFunc if successful.
fun sign(
    config: Config,
    signers: List<ID>,
    messageHash: ByteArray,
    pool: Pool? = null
): StartFunc {
    return startSign(config, signers, messageHash, pool)
}

// Presign generates a preprocessed signature that does not depend on the message being signed.
// When the message becomes available, the same participants can efficiently combine their shares
// to produce a full signature with the PresignOnline protocol.
// Note: the PreSignatures should be treated as secret key material.
// Returns a StartFunc if successful.
fun presign(
    config: Config,
    signers: List<ID>,
    pool: Pool? = null
): StartFunc {
    return StartPresign(config, signers, byteArrayOf(), pool)
}

// PresignOnline efficiently generates an ECDSA signature for `messageHash` given a preprocessed `PreSignature`.
// Returns a StartFunc if successful.
fun presignOnline(
    config: Config,
    preSignature: PreSignature,
    messageHash: ByteArray,
    pool: Pool? = null
): StartFunc {
    return StartPresignOnline(config, preSignature, messageHash, pool)
}