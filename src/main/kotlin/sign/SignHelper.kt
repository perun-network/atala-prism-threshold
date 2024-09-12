package perun_network.ecdsa_threshold.sign

import fr.acinq.secp256k1.Secp256k1
import java.math.BigInteger
import java.util.Arrays.copyOfRange

// xScalar extracts the x-coordinate from a Secp256k1 public key.
fun xScalar(bigR : ByteArray) : ByteArray {
    if (bigR.size != 65) {
        throw IllegalArgumentException("Big R must be 65 bytes, was ${bigR.size}")
    }

    // Extract the x-coordinate
    return bigR.copyOfRange(1, 33)
}