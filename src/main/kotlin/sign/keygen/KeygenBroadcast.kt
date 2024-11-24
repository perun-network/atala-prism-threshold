package perun_network.ecdsa_threshold.sign.keygen

import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.sign.Broadcast
import perun_network.ecdsa_threshold.zero_knowledge.sch.SchnorrProof

data class KeygenRound1Broadcast (
    override val ssid: ByteArray,
    override val from: Int,
    override val to: Int,
    val VShare: ByteArray
) : Broadcast(ssid, from, to)


data class KeygenRound2Broadcast (
    override val ssid: ByteArray,
    override val from: Int,
    override val to: Int,
    val rhoShare: Scalar,
    val XShare: Point,
    val AShare: Point,
    val uShare: ByteArray,
) : Broadcast(ssid, from, to) {}

data class KeygenRound3Broadcast (
    override val ssid: ByteArray,
    override val from: Int,
    override val to: Int,
    val schnorrProof: SchnorrProof,
) : Broadcast(ssid, from, to)