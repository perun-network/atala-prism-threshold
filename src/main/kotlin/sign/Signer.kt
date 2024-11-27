package perun_network.ecdsa_threshold.sign

import perun_network.ecdsa_threshold.ecdsa.*
import perun_network.ecdsa_threshold.keygen.PublicPrecomputation
import perun_network.ecdsa_threshold.keygen.SecretPrecomputation
import perun_network.ecdsa_threshold.paillier.PaillierCipherText
import perun_network.ecdsa_threshold.sign.presign.*
import perun_network.ecdsa_threshold.zero_knowledge.elog.ElogPublic
import perun_network.ecdsa_threshold.zkproof.logstar.LogStarPublic
import java.math.BigInteger

/**
 * Represents the secrets of the signer during the process of threshold signing.
 *
 * @property id The identifier of the signer.
 * @property private The signer's private precomputation, containing secret values.
 * @property publicPrecomps A map of public precomputations, indexed by the signer's IDs.
 *
 * @property kShare The signer's share of the secret value `kᵢ` in the presigning protocol (Round 1).
 * @property gammaShare The signer's share of the secret value `gammaᵢ` in the presigning protocol (Round 1).
 * @property kNonce The signer's nonce value used in the presigning protocol (Round 1).
 * @property gNonce The group's nonce value used in the presigning protocol (Round 1).
 * @property a The secret nonce used in El-Gamal encryption of kShare.
 * @property b The secret nonce used in El-Gamal encryption of gammaShare.
 * @property K The public K_i counterpart of kᵢ in the presigning protocol (Round 1).
 * @property G The public G_i counterpart of gammaᵢ in the presigning protocol (Round 1).
 * @property elGamalPublic The public points used in El-Gamal encryption.
 *
 * @property bigGammaShare The public `Γi` value produced after presigning round 2 protocol (Round 2).
 *
 * @property chiShare The signer's share of the secret value `Xᵢ` in the presigning protocol (Round 3).
 * @property deltaShare The signer's public share 'δi' in the presigning protocol (Round 3).
 * @property bigDeltaShare The signer's public delta share 'Δi' in the presigning protocol (Round 3).
 * @property bigGamma The signer's public gamma 'Γ' which is the combined bigGammaShares of all the signers from second round (Round 3).
 *
 * @property bigR Represents the public Point to be used for signing partial signature and verification (Presign Output).
 */
data class ThresholdSigner(
    val id : Int,
    val private : SecretPrecomputation,
    val publicPrecomps: Map<Int, PublicPrecomputation>,

    // PRESIGN ROUND 1
    private var kShare : Scalar? = null, // k_i
    private var gammaShare: Scalar? = null, // gamma_i
    private var kNonce : BigInteger? = null,
    private var gNonce : BigInteger? = null,
    private var a: Scalar? = null,
    private var b: Scalar? = null,

    var K : PaillierCipherText? = null,
    var G : PaillierCipherText? = null,
    var elGamalPublic: ElGamalPublic? = null,

    // PRESIGN ROUND 2
    var bigGammaShare: Point? = null,

    // PRESIGN ROUND 3
    private var chiShare: Scalar? = null, // X_i
    var deltaShare: BigInteger? = null,
    var bigDeltaShare: Point? = null,
    var bigGamma: Point? = null,

    var bigR : Point? = null,
) {
    /**
     * Executes the first round of the threshold ECDSA pre-signing process.
     *
     * This method handles Round 1 of the protocol where each signer samples secret values `ki`, `γi` and
     * generates corresponding Paillier ciphertexts `Ki`, `Gi` for the secret shares of `ki` and `γi`.
     *
     * @param signerIds List of all signers involved in the pre-signing process.
     * @return A map of broadcast messages from each signer containing the ciphertexts `Ki`, `Gi`, and proof components.
     */
    fun presignRound1(signerIds : List<Int>) : MutableMap<Int, PresignRound1Broadcast>  {
        val presignRound1Input = PresignRound1Input(
            ssid = private.ssid,
            id = id,
            publicPrecomps = publicPrecomps
        )

        // Produce Presign Round1 outputs.
        val (output, gammaShare, kShare, gNonce, kNonce, K, G, elGamalPublic, elGamalSecret) = presignRound1Input.producePresignRound1Output(signerIds)

        this.gammaShare = gammaShare
        this.kShare = kShare
        this.gNonce = gNonce
        this.kNonce = kNonce
        this.K = K
        this.G = G
        this.a = elGamalSecret.a
        this.b = elGamalSecret.b
        this.elGamalPublic = elGamalPublic
        return output
    }

    /**
     * Executes the second round of the threshold ECDSA pre-signing process.
     *
     * During this round, each signer verifies the first round outputs from other signers and produces
     * a share of the public `Γ` value, which will be used later in the signature.
     *
     * @param signerIds List of all signers.
     * @param Ks Map of public `K_i` Paillier ciphertexts from all signers.
     * @param presignRound1Broadcasts Broadcasts received in Round 1.
     * @return A map of broadcast messages for the second round, including `Γi` shares and proofs.
     */
    fun presignRound2(
        signerIds: List<Int>,
        Ks : Map<Int, PaillierCipherText>, // public K_i from all peers
        presignRound1Broadcasts: Map<Int, Map<Int, PresignRound1Broadcast>>) : Map<Int, PresignRound2Broadcast> {
        // Prepare Presign Round 2 Inputs
        val presignRound2Input = PresignRound2Input(
            ssid = private.ssid,
            id = id,
            gammaShare = gammaShare!!,
            secretECDSA = private.ecdsaShare,
            secretPaillier = private.paillierSecret ,
            gNonce = gNonce!!,
            publicPrecomps = publicPrecomps
        )

        // Verify Presign Round 1 Broadcasts
        for ((j, presign1output) in presignRound1Broadcasts) {
            if (j != id) {
                if (!presignRound2Input.verifyPresignRound1Broadcast(j, presign1output[id]!!)) {
                    throw PresignException("failed to validate enc proof for K from $j to $id")
                }
                println("Validated presign round 1 output from $j to $id ")
            }
        }

        // Produce Presign Round2 output
        val (presign2Broadcasts, bigGammaShare) = presignRound2Input.producePresignRound2Output(
            signerIds,
            Ks,
            elGamalPublic!!.B1, elGamalPublic!!.B2, elGamalPublic!!.Y, b!!)
        this.bigGammaShare = bigGammaShare

        return presign2Broadcasts
    }

    /**
     * Executes the third round of the threshold ECDSA pre-signing process.
     *
     * In this round, each signer calculates `δi` and `χi` as partial contributions to the final signature,
     * combining all the secret shares from previous rounds.
     *
     * @param signerIds List of all signers.
     * @param bigGammaShares Map of `Γi` shares from all signers.
     * @param presignRound2Broadcasts Broadcasts received in Round 2.
     * @param elGamalPublics Public points broadcast by peers for ElGamal proofs.
     * @return A map of broadcast messages for Round 3, including partial signature shares and proofs.
     */
    fun presignRound3(
        signerIds: List<Int>,
        bigGammaShares : Map<Int, Point>,
        elGamalPublics: Map<Int, ElGamalPublic>,
        presignRound2Broadcasts: Map<Int, Map<Int, PresignRound2Broadcast>>
    ) : Map<Int, PresignRound3Broadcast> {
        val presignRound3Input = PresignRound3Input(
            ssid = private.ssid,
            id = id,
            gammaShare = gammaShare!!.value,
            secretPaillier = private.paillierSecret,
            kShare = kShare!!,
            K = K!!,
            kNonce = kNonce!!,
            secretECDSA = private.ecdsaShare.value,
            publicPrecomps = publicPrecomps
        )

        // Verify Presign Round 2 Broadcasts
        for ((j, presign2output) in presignRound2Broadcasts) {
            if (j != id) {
                if (!presignRound3Input.verifyPresignRound2Broadcast(
                        j,
                        presign2output[id]!!,
                        K!!,
                        publicPrecomps[j]!!.publicEcdsa,
                        bigGammaShares[j]!!,
                        elGamalPublics[j]!!.B1,
                        elGamalPublics[j]!!.B2,
                        elGamalPublics[j]!!.Y
                    )
                ) {
                    throw PresignException("failed to validate presign round 2 broadcast from $j to $id")
                }
                println("Validated presign round 2 output from $j to $id")
            }
        }

        // Produce Presign Round 3 outputs.
        val (presign3Broadcast, chiShare, deltaShare, bigDeltaShare, bigGamma) = presignRound3Input.producePresignRound3Output(
            signerIds,
            bigGammaShares,
            elGamalPublic!!.A1, elGamalPublic!!.A2, elGamalPublic!!.Y, a!!,
            presignRound2Broadcasts)

        this.chiShare = Scalar(chiShare)
        this.deltaShare = deltaShare
        this.bigDeltaShare = bigDeltaShare
        this.bigGamma = bigGamma

        return presign3Broadcast
    }

    /**
     * Verifies the broadcast of the third round of the presigning process from a given signer.
     *
     * @param j The identifier of the signer whose output is being verified.
     * @param presignRound3Broadcast The output from the third round for the given signer.
     * @param A1j First public point A by peer for used in El-Gamal encryption of kShare.
     * @param A2j Second public point A by peer for used in El-Gamal encryption of kShare.
     * @param Yj peer's public point to be used in all El-Gamal encryption.
     * @return True if the verification is successful; otherwise, false.
     */
    private fun verifyPresignRound3Broadcast(
        j : Int,
        presignRound3Broadcast: PresignRound3Broadcast,
        A1j: Point,
        A2j: Point,
        Yj: Point
    ) : Boolean {
        // Check ssid.
        if (!private.ssid.contentEquals(presignRound3Broadcast.ssid)) {
            throw PresignException("unknown ssid ${presignRound3Broadcast.ssid}")
        }

        // Check identifier.
        if (j == id || presignRound3Broadcast.from != j || id != presignRound3Broadcast.to ) {
            throw PresignException("invalid id from ${presignRound3Broadcast.from} to ${presignRound3Broadcast.to} ")
        }

        // Check elog proof
        val elogPublic = ElogPublic(
            L = A1j,
            M = A2j,
            X = Yj,
            Y = presignRound3Broadcast.bigDeltaShare,
            h = presignRound3Broadcast.gamma
        )
        return presignRound3Broadcast.elogProof.verify(presignRound3Broadcast.from, elogPublic)
    }

    /**
     * Processes the presign output from all the signers.
     *
     * After completing the three rounds, this method combines the results to calculate the final
     * commitment point `R` to be used in the signature. The commitment `R` is derived using the
     * combined `Γ` and `δi` shares from each signer.
     *
     * @param signers List of identifiers for all signers.
     * @param presignRound3Broadcasts Broadcasts from all signers in Round 3.
     * @param deltaShares Map of `δi` shares from all signers.
     * @param bigDeltaShares Map of `Δi` shares from all signers.
     * @return The final commitment point `R`.
     */
    fun processPresignOutput(
        signers : List<Int>,
        presignRound3Broadcasts: Map<Int, Map<Int, PresignRound3Broadcast>>,
        elGamalPublics: Map<Int, ElGamalPublic>,
        deltaShares: Map<Int, BigInteger>,
        bigDeltaShares: Map<Int, Point>,
    ) {
        // Verify broadcasts from all peers
        for (j in signers) {
            if (j != id) {
                if (!verifyPresignRound3Broadcast(
                        j,
                        presignRound3Broadcasts[j]!![id]!!,
                        elGamalPublics[j]!!.A1, elGamalPublics[j]!!.A2, elGamalPublics[j]!!.Y)) {
                    throw PresignException("failed to validate presign round 3 broadcast from $j to $id")
                }
            }
        }

        // δ = ∑ⱼ δⱼ
        // Δ = ∑ⱼ Δⱼ
        var delta = Scalar.zero()
        var bigDelta = newPoint()
        for (i in signers) {
            delta = delta.add(Scalar(deltaShares[i]!!.mod(secp256k1Order())))
            bigDelta = bigDelta.add(bigDeltaShares[i]!!)
        }

        // Δ == [δ]G
        val deltaComputed = delta.actOnBase()
        if (deltaComputed != bigDelta) {
            throw Exception("computed Δ is inconsistent with [δ]G")
        }

        // R = Γ^δ−1
        val deltaInv = delta.invert()
        this.bigR = deltaInv.act(bigGamma!!)
    }

    /**
     * Generates a partial signature from the signer.
     *
     * This method allows the signer to produce a partial signature `σi` for a given message hash `H(m)`.
     * The partial signatures from all signers will be combined to form the final signature.
     *
     * @param ssid Unique session identifier.
     * @param hash The hash of the message being signed.
     * @return A partial signature containing the signer's contribution to the final signature.
     */
    fun partialSignMessage(ssid: ByteArray, hash: ByteArray): PartialSignature {
        // Check ssid.
        if (!private.ssid.contentEquals(ssid)) {
            throw PresignException("unknown ssid $ssid")
        }


        val rX = bigR!!.xScalar()
        val sigmaShare = rX.multiply(chiShare!!).add(Scalar.scalarFromByteArray(hash).multiply(kShare!!))
        return PartialSignature(
            ssid = ssid,
            id = id,
            sigmaShare = sigmaShare
        )
    }
}

/**
 * Combines partial signatures to create the final ECDSA signature.
 *
 * This function combines all partial signatures from signers to produce the final valid ECDSA signature `(r, s)`.
 * It ensures that the signature is valid with respect to the given public key and message hash.
 *
 * @param bigR The commitment point `R` from the pre-signing process.
 * @param partialSignatures A list of partial signatures from all signers.
 * @param publicPoint The public key point corresponding to the signers.
 * @param hash The hash of the message that was signed.
 * @return A complete ECDSA signature that is valid for the provided message and public key.
 */
fun combinePartialSignatures(bigR: Point, partialSignatures : List<PartialSignature>, publicPoint: Point, hash : ByteArray) : Signature {
    val r = bigR.xScalar()
    var sigma = Scalar.zero()
    for (partial in partialSignatures) {
        sigma = sigma.add(partial.sigmaShare)
    }

    val signature = Signature.newSignature(r, sigma)

    if (!signature.verifyWithPoint(hash, publicPoint)) {
        throw IllegalStateException("invalid signature")
    }

    return signature
}
