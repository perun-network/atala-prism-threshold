package perun_network.ecdsa_threshold.sign.aux

/**
 * Custom exception for handling errors related to Auxiliary-Info & Key Refresh protocols.
 *
 * @param message The detail message for the exception, which provides information
 * about the error.
 */
class AuxException(message: String) : Exception(message)