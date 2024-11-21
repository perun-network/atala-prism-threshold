package perun_network.ecdsa_threshold.sign.keygen

import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.zero_knowledge.sch.SchnorrProof

data class KeygenRound1Broadcast (
    val ssid: ByteArray,
    val from: Int,
    val to: Int,
    val VShare: ByteArray
)


data class KeygenRound2Broadcast (
    val ssid: ByteArray,
    val from: Int,
    val to: Int,
    val rhoShare: Scalar,
    val XShare: Point,
    val AShare: Point,
    val uShare: ByteArray,
)

data class KeygenRound3Broadcast (
    val ssid: ByteArray,
    val from: Int,
    val to: Int,
    val schnorrProof: SchnorrProof,
)