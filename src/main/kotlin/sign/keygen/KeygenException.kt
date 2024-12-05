package perun_network.ecdsa_threshold.sign.keygen

/**
 * Custom exception for handling errors related to Key-Generation protocol.
 *
 * This exception is thrown to indicate an error that occurs during the execution of the protocol.
 *
 * @param message The detail message for the exception, which provides information
 * about the error.
 */
class KeygenException(message: String) : Exception(message)