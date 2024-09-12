package perun_network.ecdsa_threshold.presign

import java.math.BigInteger

class PresignRound3Input(
    val ssid: ByteArray,
    val id: Int,
    val bigGammaShare: BigInteger
)
