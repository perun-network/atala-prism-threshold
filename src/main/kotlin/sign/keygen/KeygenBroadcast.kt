package perun_network.ecdsa_threshold.sign.keygen

import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.sign.Broadcast
import perun_network.ecdsa_threshold.zero_knowledge.SchnorrProof

/**
 * Represents the broadcast message in the first round of the key generation process.
 *
 * @property ssid The unique session identifier for the protocol.
 * @property from The identifier of the party sending this broadcast message.
 * @property to The identifier of the party receiving this broadcast message.
 * @property VShare The shared value that is part of the key generation process.
 */
data class KeygenRound1Broadcast (
    override val ssid: ByteArray,
    override val from: Int,
    override val to: Int,
    val VShare: ByteArray
) : Broadcast(ssid, from, to)

/**
 * Represents the broadcast message in the second round of the key generation process.
 *
 * @property ssid The unique session identifier for the protocol.
 * @property from The identifier of the party sending this broadcast message.
 * @property to The identifier of the party receiving this broadcast message.
 * @property rhoShare The share of the value ρ, which is used in the protocol.
 * @property XShare The public share of the private key for the sender.
 * @property AShare The commitment associated with the private share.
 * @property uShare A random value shared between parties.
 */
data class KeygenRound2Broadcast (
    override val ssid: ByteArray,
    override val from: Int,
    override val to: Int,
    val rhoShare: Scalar,
    val XShare: Point,
    val AShare: Point,
    val uShare: ByteArray,
) : Broadcast(ssid, from, to) {}

/**
 * Represents the broadcast message in the third round of the key generation process.
 *
 * @property ssid The unique session identifier for the protocol.
 * @property from The identifier of the party sending this broadcast message.
 * @property to The identifier of the party receiving this broadcast message.
 * @property schnorrProof The Schnorr proof that verifies the validity of the public share.
 */
data class KeygenRound3Broadcast (
    override val ssid: ByteArray,
    override val from: Int,
    override val to: Int,
    val schnorrProof: SchnorrProof,
) : Broadcast(ssid, from, to)