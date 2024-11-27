package perun_network.ecdsa_threshold.sign

/**
 * Represents a broadcast message with basic metadata.
 *
 * @param ssid A unique identifier for the broadcast (could represent session ID).
 * @param from The identifier of the sender (typically a participant index or node).
 * @param to The identifier of the recipient (typically a participant index or node).
 */
open class Broadcast (
    open val ssid: ByteArray,
    open val from : Int,
    open val to: Int,
)
