package perun_network.ecdsa_threshold.sign.aux

import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.math.shamir.ExponentPolynomial
import perun_network.ecdsa_threshold.paillier.PaillierCipherText
import perun_network.ecdsa_threshold.paillier.PaillierPublic
import perun_network.ecdsa_threshold.pedersen.PedersenParameters
import perun_network.ecdsa_threshold.sign.Broadcast
import perun_network.ecdsa_threshold.sign.presign.ElGamalPublic
import perun_network.ecdsa_threshold.zero_knowledge.fac.FacCommitment
import perun_network.ecdsa_threshold.zero_knowledge.fac.FacProof
import perun_network.ecdsa_threshold.zero_knowledge.mod.ModProof
import perun_network.ecdsa_threshold.zero_knowledge.prm.PrmProof
import perun_network.ecdsa_threshold.zero_knowledge.sch.SchnorrCommitment
import perun_network.ecdsa_threshold.zero_knowledge.sch.SchnorrProof

/**
 * Represents the first round of auxiliary broadcasting in the protocol.
 *
 * @property ssid The unique session identifier for the protocol.
 * @property from The identifier of the sender party.
 * @property to The identifier of the recipient party.
 * @property VHash A hash value used to verify the broadcast message.
 */
data class AuxRound1Broadcast (
    override val ssid: ByteArray,
    override val from: Int,
    override val to: Int,
    val VHash: ByteArray
) : Broadcast(ssid, from, to)


/**
 * Represents the second round of auxiliary broadcasting in the protocol.
 *
 * @property ssid The unique session identifier for the protocol.
 * @property from The identifier of the sender party.
 * @property to The identifier of the recipient party.
 * @property ePolyShare The exponent polynomial shared by the sender.
 * @property As A map of public Schnorr's commitments from the parties.
 * @property paillierPublic The public key for Paillier encryption.
 * @property pedersenPublic The public parameters for the Pedersen commitment.
 * @property rid A random identifier used for the protocol.
 * @property uShare A random value shared by the sender.
 * @property prmProof A proof for the Pedersen commitment.
 */
data class AuxRound2Broadcast (
    override val ssid: ByteArray,
    override val from: Int,
    override val to: Int,
    val ePolyShare: ExponentPolynomial,
    val As: Map<Int, Point>,
    val paillierPublic: PaillierPublic,
    val pedersenPublic: PedersenParameters,
    val rid: ByteArray,
    val uShare: ByteArray,
    val prmProof: PrmProof
) : Broadcast(ssid, from, to) {}

/**
 * Represents the third round of auxiliary broadcasting in the protocol.
 *
 * @property ssid The unique session identifier for the protocol.
 * @property from The identifier of the sender party.
 * @property to The identifier of the recipient party.
 * @property modProof A proof for the modulus of N in the Paillier encryption.
 * @property facProof A proof for the factorization of the Paillier modulus.
 * @property schProofs A map of Schnorr proofs for the commitments.
 * @property CShare The Paillier ciphertext representing the sender's share to be sent.
 */
data class AuxRound3Broadcast (
    override val ssid: ByteArray,
    override val from: Int,
    override val to: Int,
    val modProof : ModProof,
    val facProof : FacProof,
    val schProofs : Map<Int, SchnorrProof>,
    val CShare: PaillierCipherText
) : Broadcast(ssid, from, to) {}