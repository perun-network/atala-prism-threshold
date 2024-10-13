package perun_network.ecdsa_threshold.zero_knowledge

/**
 * Custom exception for handling errors related to Zero-Knowledge protocols.
 *
 * This exception is thrown to indicate an error that occurs during the execution
 * of zero-knowledge proofs or related operations. It provides constructors for
 * different scenarios of error handling.
 *
 * @param message The detail message for the exception, which provides information
 * about the error.
 *
 * @constructor Creates an instance of [ZeroKnowledgeException] with a specified message.
 *
 * @param message The detail message.
 * @param cause The cause of the exception (another throwable).
 */
class ZeroKnowledgeException(message: String) : Exception(message)