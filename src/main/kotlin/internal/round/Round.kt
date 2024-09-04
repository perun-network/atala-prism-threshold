package perun_network.ecdsa_threshold.internal.round

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.SendChannel


interface Round {
    // VerifyMessage handles an incoming Message and validates its content with regard to the protocol specification.
    // The content argument can be cast to the appropriate type for this round without error check.
    // In the first round, this function returns null.
    // This function should not modify any saved state as it may be running concurrently.
    suspend fun verifyMessage(msg: Message): Exception?

    // StoreMessage should be called after VerifyMessage and should only store the appropriate fields from the content.
    fun storeMessage(msg: Message): Exception?

    // Finalize is called after all messages from the parties have been processed in the current round.
    // Messages for the next round are sent out through the out channel.
    // If a non-critical error occurs (like a failure to sample, hash, or send a message), the current round can be
    // returned so that the caller may try to finalize again.
    //
    // If an abort occurs, the expected behavior is to return
    //   r.abortRound(err, culprits), null
    // This indicates to the caller that the protocol has aborted due to a "math" error.
    //
    // In the last round, Finalize should return
    //   r.resultRound(result), null
    // where result is the output of the protocol.
    suspend fun finalize(out: Channel<Message>): Pair<Session?, Exception?>

    // MessageContent returns an uninitialized message.Content for this round.
    //
    // The first round of a protocol should return null.
    fun messageContent(): Content?

    // Number returns the current round number.
    fun number(): Number
}

interface BroadcastRound : Round {
    // StoreBroadcastMessage must be run before Round.verifyMessage and Round.storeMessage,
    // since those may depend on the content from the broadcast.
    // It changes the round's state to store the message after performing basic validation.
    suspend fun storeBroadcastMessage(msg: Message): Exception?

    // BroadcastContent returns an uninitialized message.Content for this round's broadcast message.
    //
    // The first round of a protocol, and rounds which do not expect a broadcast message should return null.
    fun broadcastContent(): BroadcastContent?
}