package perun_network.ecdsa_threshold.presign

import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.hash.Hash
import perun_network.ecdsa_threshold.math.sampleScalar
import perun_network.ecdsa_threshold.paillier.PaillierCipherText
import perun_network.ecdsa_threshold.paillier.PaillierPublic
import perun_network.ecdsa_threshold.pedersen.PedersenParameters
import perun_network.ecdsa_threshold.zkproof.affg.AffgProof
import perun_network.ecdsa_threshold.zkproof.enc.EncPrivate
import perun_network.ecdsa_threshold.zkproof.enc.EncProof
import perun_network.ecdsa_threshold.zkproof.enc.EncPublic
import perun_network.ecdsa_threshold.zkproof.logstar.LogStarProof
import java.math.BigInteger

class PresignRound1Output (
    val ssid: ByteArray,
    val id : Int,
    val K : PaillierCipherText, // K = K_i
    val G: PaillierCipherText, // G = G_i
    val proof: EncProof,
)

class PresignRound1Input (
    val ssid: ByteArray,
    val id: Int,
    val paillier: PaillierPublic,
    val prover: Map<Int, PaillierPublic>,
    val pedersen: Map<Int, PedersenParameters>,
) {
    fun producePresignRound1Output(
        otherPartys: List<Int>
    ) : Map<Int, PresignRound1Output> {
        val result = mutableMapOf<Int, PresignRound1Output>()
        // sample γi ← Fq
        val gammaShare = sampleScalar()
        // Gᵢ = Encᵢ(γᵢ;νᵢ)
        val (G, gNonce) = paillier.enc(gammaShare.value)

        // kᵢ <- 𝔽,
        val kShare = sampleScalar()
        val (K, kNonce) = paillier.enc(kShare.value)
        for (j in otherPartys) {
            // Compute ψ_0_j,i = M(prove, Πenc_j,(ssid, i),(Iε, Ki); (ki, ρi)) for every j 6= i.
            val proof = EncProof.newProof(Hash.hashWithID(id),
                EncPublic(K, prover[id]!!, pedersen[j]!!),
                EncPrivate(kShare.value, kNonce))

            result[j] = PresignRound1Output(
                ssid = ssid,
                id = id,
                K = K,
                G = G,
                proof = proof
            )
        }
        return result
    }

}