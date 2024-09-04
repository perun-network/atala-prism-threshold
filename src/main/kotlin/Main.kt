package perun_network.ecdsa_threshold

import kotlinx.coroutines.*
import perun_network.ecdsa_threshold.party.ID
import perun_network.ecdsa_threshold.network.Network
import perun_network.ecdsa_threshold.pool.Pool
import perun_network.ecdsa_threshold.protocol.MultiHandler
import perun_network.ecdsa_threshold.protocol.MultiHandler.Companion.newMultiHandler

fun main() = runBlocking {
    val ids = mutableListOf(ID("a"), ID("b"), ID("c"), ID("d"), ID("e"), ID("f"))
    val threshold = 4
    val messageToSign = "I need signing".toByteArray()

    val net = Network(ids)

    val jobs = mutableListOf<Job>()
    for (id in ids) {
        jobs.add(launch {
            val pl = Pool.newPool(0)
            try {
                all(id, ids, threshold, messageToSign, net, pl)
            } catch (e: Exception) {
                println(e.message)
            } finally {
                pl.tearDown()
            }
        })
    }
    jobs.forEach { it.join() }
}


suspend fun XOR(id: ID, ids: List<ID>, net: Network) {
    val handler = Example.startXOR(id, ids)
    net.handlerLoop(id, handler)
    val result = handler.result()
    if (result == null) throw Exception("XOR failed for ID: $id")
}

suspend fun CMPKeygen(id: ID, ids: List<ID>, threshold: Int, net: Network, pl: Pool): CMP.Config {
    val handler = newMultiHandler(keygen(id, ids, threshold, pl)
    net.handlerLoop(id, handler)
    val result = handler.result() as CMP.Config?
    return result ?: throw Exception("CMP Keygen failed for ID: $id")
}

suspend fun CMPRefresh(config: CMP.Config, net: Network, pl: Pool): CMP.Config {
    val handler = CMP.refresh(config, pl)
    net.handlerLoop(config.id, handler)
    val result = handler.result() as CMP.Config?
    return result ?: throw Exception("CMP Refresh failed for ID: ${config.id}")
}

suspend fun CMPSign(config: CMP.Config, message: ByteArray, signers: List<ID>, net: Network, pl: Pool) {
    val handler = CMP.sign(config, signers, message, pl)
    net.handlerLoop(config.id, handler)
    val result = handler.result() as CMP.Signature?
    if (result == null || !result.verify(config.publicPoint, message)) {
        throw Exception("CMP Signature verification failed")
    }
}

suspend fun CMPPreSign(config: CMP.Config, signers: List<ID>, net: Network, pl: Pool): CMP.PreSignature {
    val handler = CMP.presign(config, signers, pl)
    net.handlerLoop(config.id, handler)
    val result = handler.result() as CMP.PreSignature?
    if (result == null || !result.validate()) {
        throw Exception("CMP PreSignature validation failed")
    }
    return result
}

suspend fun CMPPreSignOnline(config: CMP.Config, preSignature: CMP.PreSignature, message: ByteArray, net: Network, pl: Pool) {
    val handler = CMP.presignOnline(config, preSignature, message, pl)
    net.handlerLoop(config.id, handler)
    val result = handler.result() as CMP.Signature?
    if (result == null || !result.verify(config.publicPoint, message)) {
        throw Exception("CMP Online Signature verification failed")
    }
}

suspend fun FrostKeygen(id: ID, ids: List<ID>, threshold: Int, net: Network): Frost.Config {
    val handler = Frost.keygen(id, ids, threshold)
    net.handlerLoop(id, handler)
    val result = handler.result() as Frost.Config?
    return result ?: throw Exception("Frost Keygen failed for ID: $id")
}

suspend fun FrostSign(config: Frost.Config, id: ID, message: ByteArray, signers: List<ID>, net: Network) {
    val handler = Frost.sign(config, signers, message)
    net.handlerLoop(id, handler)
    val result = handler.result() as Frost.Signature?
    if (result == null || !result.verify(config.publicKey, message)) {
        throw Exception("Frost Signature verification failed")
    }
}

suspend fun FrostKeygenTaproot(id: ID, ids: List<ID>, threshold: Int, net: Network): Frost.TaprootConfig {
    val handler = Frost.keygenTaproot(id, ids, threshold)
    net.handlerLoop(id, handler)
    val result = handler.result() as Frost.TaprootConfig?
    return result ?: throw Exception("Frost Keygen Taproot failed for ID: $id")
}

suspend fun FrostSignTaproot(config: Frost.TaprootConfig, id: ID, message: ByteArray, signers: List<ID>, net: Network) {
    val handler = Frost.signTaproot(config, signers, message)
    net.handlerLoop(id, handler)
    val result = handler.result() as Frost.TaprootSignature?
    if (result == null || !config.publicKey.verify(result, message)) {
        throw Exception("Frost Taproot Signature verification failed")
    }
}

suspend fun all( id: ID,
                 ids: List<ID>,
                 threshold: Int,
                 messageToSign: ByteArray,
                 net: Network,
                 pl: Pool ) : Boolean {
    // XOR Protocol
    try {
        XOR(id, ids, net)
    } catch (e: Exception) {
        println("XOR Error: ${e.message}")
        return false
    }

    // CMP Keygen
    val cmpConfig = try {
        CMPKeygen(id, ids, threshold, net, pl)
    } catch (e: Exception) {
        println("CMP Keygen Error: ${e.message}")
        return false
    }

    // CMP Refresh
    val refreshConfig = try {
        CMPRefresh(cmpConfig, net, pl)
    } catch (e: Exception) {
        println("CMP Refresh Error: ${e.message}")
        return false
    }

    // FROST Keygen
    val frostConfig = try {
        FrostKeygen(id, ids, threshold, net)
    } catch (e: Exception) {
        println("FROST Keygen Error: ${e.message}")
        return false
    }

    // FROST Keygen Taproot
    val frostTaprootConfig = try {
        FrostKeygenTaproot(id, ids, threshold, net)
    } catch (e: Exception) {
        println("FROST Keygen Taproot Error: ${e.message}")
        return false
    }

    val signers = ids.take(threshold + 1)
    if (id !in signers) {
        net.quit(id)
        return true
    }

    // CMP Sign
    try {
        CMPSign(refreshConfig, messageToSign, signers, net, pl)
    } catch (e: Exception) {
        println("CMP Sign Error: ${e.message}")
        return false
    }

    // CMP PreSign
    val preSignature = try {
        CMPPreSign(refreshConfig, signers, net, pl)
    } catch (e: Exception) {
        println("CMP PreSign Error: ${e.message}")
        return false
    }

    // CMP PreSign Online
    try {
        CMPPreSignOnline(refreshConfig, preSignature, messageToSign, net, pl)
    } catch (e: Exception) {
        println("CMP PreSign Online Error: ${e.message}")
        return false
    }

    // FROST Sign
    try {
        FrostSign(frostConfig, id, messageToSign, signers, net)
    } catch (e: Exception) {
        println("FROST Sign Error: ${e.message}")
        return false
    }

    // FROST Sign Taproot
    try {
        FrostSignTaproot(frostTaprootConfig, id, messageToSign, signers, net)
    } catch (e: Exception) {
        println("FROST Sign Taproot Error: ${e.message}")
        return false
    }

    return true
}