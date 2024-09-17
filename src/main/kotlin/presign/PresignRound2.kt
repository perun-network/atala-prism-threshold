package perun_network.ecdsa_threshold.presign

import perun_network.ecdsa_threshold.ecdsa.Point
import java.math.BigInteger

data class PresignRound2Output (
    val ssid: ByteArray,
    val id : Int,
    val kShare : BigInteger,
    val gShare : BigInteger,
    val bigDeltaShare : Point,
    val gamma : Point,
) {
    fun generatePresignRound2output(

    ) :
}