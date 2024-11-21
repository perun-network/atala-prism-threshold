package perun_network.ecdsa_threshold.sign.aux

/**
 * Custom exception for handling errors related to Auxiliary-Info & Key Refresh protocols.
 *
 * This exception is thrown to indicate an error that occurs during the verification
 * of zero-knowledge proofs or related operations. It provides constructors for
 * different scenarios of error handling.
 *
 * @param message The detail message for the exception, which provides information
 * about the error.
 */
class AuxException(message: String) : Exception(message)