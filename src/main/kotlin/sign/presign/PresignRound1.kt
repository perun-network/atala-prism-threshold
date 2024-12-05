package perun_network.ecdsa_threshold.sign.presign

import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.keygen.PublicPrecomputation
import perun_network.ecdsa_threshold.math.sampleScalar
import perun_network.ecdsa_threshold.paillier.PaillierCipherText
import perun_network.ecdsa_threshold.sign.Broadcast
import perun_network.ecdsa_threshold.tuple.Nonuple
import perun_network.ecdsa_threshold.zero_knowledge.EncElgPrivate
import perun_network.ecdsa_threshold.zero_knowledge.EncElgProof
import perun_network.ecdsa_threshold.zero_knowledge.EncElgPublic
import java.math.BigInteger

/**
 * Represents the public parameters for ElGamal encryption.
 *
 * @property A1 Elliptic curve point representing g^a.
 * @property A2 Elliptic curve point representing h^a.
 * @property B1 Elliptic curve point representing g^b.
 * @property B2 Elliptic curve point representing h^b.
 * @property Y Elliptic curve point representing the ciphertext or an associated value (e.g., g^x or g^m).
 */
data class ElGamalPublic(
    val A1: Point,
    val A2: Point,
    val B1: Point,
    val B2: Point,
    val Y: Point
)


/**
 * Represents the secret parameters for ElGamal encryption.
 *
 * @property a Scalar representing the secret exponent a used for encryption of kShare.
 * @property b Scalar representing the secret exponent b used for encryption of gammaShare.
 */
data class ElGamalSecret(
    val a: Scalar,
    val b: Scalar,
)

/**
 * Represents the content of the message that the signer sends to its peer after the first presign round.
 *
 * @property ssid A unique identifier for the session.
 * @property from The identifier of the signer.
 * @property to The identifier of the receiver.
 * @property K The ciphertext representing Kᵢ.
 * @property G The ciphertext representing Gᵢ.
 * @property elGamalPublic The public points used for El-Gamal related encryption.
 * @property proof0 The enc-elg proof associated with K.
 * @property proof1 The enc-elg proof associated with G.
 *
 */
class PresignRound1Broadcast (
    override val ssid: ByteArray,
    override val from : Int,
    override val to: Int,
    val K : PaillierCipherText, // K = K_i
    val G: PaillierCipherText, // G = G_i
    val elGamalPublic: ElGamalPublic,
    val proof0: EncElgProof,
    val proof1: EncElgProof
) : Broadcast(ssid, from, to)

/**
 * Represents the input for the first round of the presigning process.
 *
 * @property ssid A unique identifier for the session.
 * @property id The identifier of the signer.
 * @property publicPrecomps A map of public precomputed values indexed by signer identifiers.
 *
 */
class PresignRound1Input (
    val ssid: ByteArray,
    val id: Int,
    val publicPrecomps : Map<Int, PublicPrecomputation>
) {
    /**
     * Produces the output for the first round of the presigning process.
     *
     * This method generates necessary ciphertexts and a proof for each signer.
     *
     * @param signers A list of signer identifiers participating in the presigning.
     * @return A [Nonuple] containing the results of the presigning, including the outputs for each signer,
     *         gamma share, k share, nonces, and ElGamal public and secret materials.
     */
    internal fun producePresignRound1Output(
        signers: List<Int>
    ) : Nonuple<MutableMap<Int, PresignRound1Broadcast>, Scalar, Scalar, BigInteger, BigInteger, PaillierCipherText, PaillierCipherText, ElGamalPublic, ElGamalSecret> {
        val result = mutableMapOf<Int, PresignRound1Broadcast>()
        // sample gamma_i ← Fq
        val gammaShare = sampleScalar()
        // Gᵢ = Encᵢ(γᵢ;gammaᵢ)
        val paillier = publicPrecomps[id]!!.paillierPublic
        val (G, gNonce) = paillier.encryptRandom(gammaShare.value)

        // kᵢ <- 𝔽,
        val kShare = sampleScalar()
        val (K, kNonce) = paillier.encryptRandom(kShare.value)

        // sample Y_i <- G and ai, bi ← Fq
        val yi = sampleScalar()
        val Yi = yi.actOnBase()
        val ai = sampleScalar()
        val bi = sampleScalar()

        val A1 = ai.actOnBase()
        val A2 = ai.act(Yi).add(kShare.actOnBase())
        val B1 = bi.actOnBase()
        val B2 = bi.act(Yi).add(gammaShare.actOnBase())

        val elGamalPublic = ElGamalPublic(A1, A2, B1, B2, Yi)
        val elGamalSecret = ElGamalSecret(ai, bi)


        for (j in signers) {
            if (id != j) {
                // Compute ψ_0_j,i = M(prove, Πenc_j,(ssid, i),(Iε, Ki); (ki, ρi)) for every j 6= i.
                val proof0 = EncElgProof.newProof(
                    id,
                    EncElgPublic(K, Yi, A1, A2, publicPrecomps[id]!!.paillierPublic, publicPrecomps[j]!!.aux),
                    EncElgPrivate(kShare.value, kNonce, yi, ai)
                )

                val proof1 = EncElgProof.newProof(
                    id,
                    EncElgPublic(G, Yi, B1, B2, publicPrecomps[id]!!.paillierPublic, publicPrecomps[j]!!.aux),
                    EncElgPrivate(gammaShare.value, gNonce, yi, bi)
                )


                result[j] = PresignRound1Broadcast(
                    ssid = ssid,
                    from = id,
                    to = j,
                    K = K,
                    G = G,
                    elGamalPublic = elGamalPublic,
                    proof0 = proof0,
                    proof1 = proof1
                )
            }
        }
        return Nonuple(result , gammaShare, kShare , gNonce, kNonce, K, G, elGamalPublic, elGamalSecret)
    }

}