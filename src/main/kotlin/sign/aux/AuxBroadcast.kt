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

data class AuxRound1Broadcast (
    override val ssid: ByteArray,
    override val from: Int,
    override val to: Int,
    val VHash: ByteArray
) : Broadcast(ssid, from, to)

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

data class AuxRound3Broadcast (
    override val ssid: ByteArray,
    override val from: Int,
    override val to: Int,
    val modProof : ModProof,
    val facProof : FacProof,
    val schProofs : Map<Int, SchnorrProof>,
    val CShare: PaillierCipherText
) : Broadcast(ssid, from, to) {}