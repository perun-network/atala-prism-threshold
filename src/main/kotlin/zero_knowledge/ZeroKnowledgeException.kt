package perun_network.ecdsa_threshold.zero_knowledge

// Custom exception for Zero-Knowledge related errors
class ZeroKnowledgeException(message: String) : Exception(message) {

    constructor(message: String, cause: Throwable) : this(message) {
        initCause(cause)
    }

    constructor() : this("An error occurred in the Zero-Knowledge protocol.")
}