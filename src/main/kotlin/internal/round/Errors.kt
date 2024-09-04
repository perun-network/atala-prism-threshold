package perun_network.ecdsa_threshold.internal.round

// Define custom exception classes for specific error cases
object RoundErrors {
    val ErrNilFields = IllegalArgumentException("Message contained empty fields")
    val ErrInvalidContent = IllegalArgumentException("Content is not the right type")
    val ErrOutChanFull = IllegalStateException("Output channel is full")
}