package perun_network.ecdsa_threshold.presign

import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.keygen.PublicPrecomputation
import perun_network.ecdsa_threshold.math.sampleScalar
import perun_network.ecdsa_threshold.paillier.PaillierCipherText
import perun_network.ecdsa_threshold.tuple.Septuple
import perun_network.ecdsa_threshold.zkproof.enc.EncPrivate
import perun_network.ecdsa_threshold.zkproof.enc.EncProof
import perun_network.ecdsa_threshold.zkproof.enc.EncPublic
import java.math.BigInteger

/**
 * Represents the output of the first round of the presigning process.
 *
 * @property ssid A unique identifier for the session.
 * @property id The identifier of the signer.
 * @property K The ciphertext representing Kᵢ.
 * @property G The ciphertext representing Gᵢ.
 * @property proof The cryptographic proof associated with the presigning.
 *
 */
class PresignRound1Output (
    val ssid: ByteArray,
    val id : Int,
    val K : PaillierCipherText, // K = K_i
    val G: PaillierCipherText, // G = G_i
    val proof: EncProof,
)

/**
 * Represents the input for the first round of the presigning process.
 *
 * @property ssid A unique identifier for the session.
 * @property id The identifier of the signer.
 * @property publics A map of public precomputed values indexed by signer identifiers.
 *
 */
class PresignRound1Input (
    val ssid: ByteArray,
    val id: Int,
    val publics : Map<Int, PublicPrecomputation>
) {
    /**
     * Produces the output for the first round of the presigning process.
     *
     * This method generates necessary ciphertexts and a proof for each signer.
     *
     * @param signers A list of signer identifiers participating in the presigning.
     * @return A [Septuple] containing the results of the presigning, including the outputs for each signer,
     *         gamma share, k share, and nonces.
     */
    fun producePresignRound1Output(
        signers: List<Int>
    ) : Septuple<MutableMap<Int, PresignRound1Output>, Scalar, Scalar, BigInteger, BigInteger, PaillierCipherText, PaillierCipherText> {
        val result = mutableMapOf<Int, PresignRound1Output>()
        // sample γi ← Fq
        val gammaShare = sampleScalar()
        // Gᵢ = Encᵢ(γᵢ;νᵢ)
        val paillier = publics[id]!!.paillierPublic
        val (G, gNonce) = paillier.encryptRandom(gammaShare.value)

        // kᵢ <- 𝔽,
        val kShare = sampleScalar()
        val (K, kNonce) = paillier.encryptRandom(kShare.value)
        for (j in signers) {
            if (id != j) {
                // Compute ψ_0_j,i = M(prove, Πenc_j,(ssid, i),(Iε, Ki); (ki, ρi)) for every j 6= i.
                val proof = EncProof.newProof(
                    id,
                    EncPublic(K, publics[id]!!.paillierPublic, publics[j]!!.aux),
                    EncPrivate(kShare.value, kNonce)
                )

                result[j] = PresignRound1Output(
                    ssid = ssid,
                    id = id,
                    K = K,
                    G = G,
                    proof = proof
                )
            }
        }
        return Septuple(result , gammaShare, kShare , gNonce, kNonce, K, G)
    }

}