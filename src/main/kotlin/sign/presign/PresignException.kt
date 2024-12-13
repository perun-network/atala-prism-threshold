package perun_network.ecdsa_threshold.sign.presign

/**
 * Custom exception for handling errors related to the Presigning protocol.
 *
 * @param message The detail message for the exception, which provides information
 * about the error.
 */
class PresignException(message: String) : Exception(message)