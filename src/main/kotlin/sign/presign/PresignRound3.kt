package perun_network.ecdsa_threshold.sign.presign

import perun_network.ecdsa_threshold.ecdsa.*
import perun_network.ecdsa_threshold.precomp.PublicPrecomputation
import perun_network.ecdsa_threshold.paillier.PaillierCipherText
import perun_network.ecdsa_threshold.paillier.PaillierSecret
import perun_network.ecdsa_threshold.sign.Broadcast
import perun_network.ecdsa_threshold.tuple.Quintuple
import perun_network.ecdsa_threshold.zero_knowledge.elog.ElogPrivate
import perun_network.ecdsa_threshold.zero_knowledge.elog.ElogProof
import perun_network.ecdsa_threshold.zero_knowledge.elog.ElogPublic
import perun_network.ecdsa_threshold.zero_knowledge.affg.AffgPublic
import java.math.BigInteger

/**
 * Represents the content of the message that the signer sends to its peer after the third presign round.
 *
 * @property ssid A unique identifier for the session.
 * @property from The identifier of the signer.
 * @property to The identifier of the receiver.
 * @property chiShare The computed chi share for the signer.
 * @property deltaShare The computed delta share for the signer.
 * @property bigDeltaShare The computed big delta share for the signer.
 * @property gamma The computed gamma point for the signer.
 * @property elogProof The elog proof associated with the presigning process.
 */
data class PresignRound3Broadcast (
    override val ssid: ByteArray,
    override val from : Int,
    override val to: Int,
    val chiShare : BigInteger,
    val deltaShare : BigInteger,
    val bigDeltaShare : Point,
    val gamma : Point,
    val elogProof: ElogProof
) : Broadcast(ssid, from, to)

/**
 * Represents the input for the third round of the presigning process.
 *
 * @property ssid A unique identifier for the session.
 * @property id The identifier of the signer.
 * @property gammaShare The gamma share for the signer.
 * @property secretPaillier The Paillier secret key for the signer.
 * @property kShare The scalar value for k.
 * @property K The Paillier ciphertext for K.
 * @property kNonce The nonce used for generating the proof.
 * @property secretECDSA The ECDSA secret key for the signer.
 * @property publicPrecomps A map of public precomputed values indexed by signer identifiers.
 */
class PresignRound3Input(
    val ssid: ByteArray,
    val id: Int,
    val gammaShare : BigInteger,
    val secretPaillier: PaillierSecret,
    val kShare: Scalar,
    val K : PaillierCipherText,
    val kNonce: BigInteger,
    val secretECDSA: BigInteger,
    val publicPrecomps: Map<Int, PublicPrecomputation>
) {
    /**
     * Produces the output for the third round of the presigning process.
     *
     * This method generates the necessary shares and proofs for each signer.
     *
     * @param signers A list of signer identifiers participating in the presigning.
     * @param bigGammaShares A map of big gamma shares indexed by signer identifiers.
     * @param A1 The first public point A used for El-Gamal encryption of k.
     * @param A2 The second public point A used for El-Gamal encryption of k.
     * @param Yi The public point used in El-Gamal encryption.
     * @param a The secret Scalar used to encrypt kShare.
     * @param presignRound2Broadcasts A map of broadcasts from the second round indexed by signer identifiers.
     * @return A quintuple containing a map of the presign outputs for each signer, the computed chi share,
     *         the computed delta share, the computed big delta share, and the computed gamma point.
     */
    internal fun producePresignRound3Output(
        signers : List<Int>,
        bigGammaShares : Map<Int,Point>,
        A1 : Point,
        A2: Point,
        Yi: Point,
        a: Scalar,
        presignRound2Broadcasts:  Map<Int, PresignRound2Broadcast>
    ) : Quintuple<Map<Int, PresignRound3Broadcast>, BigInteger, BigInteger, Point, Point>{
        val  result = mutableMapOf<Int, PresignRound3Broadcast>()
        val deltaShareAlphas= mutableMapOf<Int, BigInteger>() // DeltaShareAlpha[j] = αᵢⱼ
        val deltaShareBetas= mutableMapOf<Int, BigInteger>()  // DeltaShareBeta[j] = βᵢⱼ
        val chiShareAlphas= mutableMapOf<Int, BigInteger>()   // ChiShareAlpha[j] = α̂ᵢⱼ
        val chiShareBetas= mutableMapOf<Int, BigInteger>()   // ChiShareBeta[j] = β̂^ᵢⱼ
        for (j in signers) {
            if (j != id) {
                deltaShareBetas[j] = presignRound2Broadcasts[j]!!.deltaBeta
                chiShareBetas[j] = presignRound2Broadcasts[j]!!.chiBeta
                deltaShareAlphas[j] = secretPaillier.decrypt(presignRound2Broadcasts[j]!!.deltaD)
                chiShareAlphas[j] = secretPaillier.decrypt(presignRound2Broadcasts[j]!!.chiD)
                chiShareAlphas[j] = secretPaillier.decrypt(presignRound2Broadcasts[j]!!.chiD)
            }
        }


        // Γ = ∑ⱼ Γⱼ
        var bigGamma = newPoint()
        for ((_, bigGammaShare) in bigGammaShares) {
            bigGamma = bigGamma.add(bigGammaShare)
        }

        // Δᵢ = [kᵢ]Γ
        val bigDeltaShare = kShare.act(bigGamma)

        // δᵢ = γᵢ kᵢ
        var deltaShare = gammaShare.multiply(kShare.value)

        // χᵢ = xᵢ kᵢ
        var chiShare = secretECDSA.multiply(kShare.value)

        for (j in signers) {
            if (j != this.id) {
                //δᵢ += αᵢⱼ + βᵢⱼ
                deltaShare = deltaShare.add(deltaShareAlphas[j])
                deltaShare = deltaShare.add(deltaShareBetas[j])

                // χᵢ += α̂ᵢⱼ +  ̂βᵢⱼ
                chiShare = chiShare.add(chiShareAlphas[j])
                chiShare = chiShare.add(chiShareBetas[j])
            }
        }
        deltaShare = deltaShare.mod(secp256k1Order())
        chiShare = chiShare.mod(secp256k1Order())
        for (j in signers) {
            if (j != id) {
                val elogPublic = ElogPublic(
                    L = A1,
                    M = A2,
                    X = Yi,
                    Y = bigDeltaShare,
                    h = bigGamma,
                )

                val elogPrivate = ElogPrivate(
                    y= kShare,
                    lambda= a
                )
                val elogProof = ElogProof.newProof(id, elogPublic, elogPrivate)
                result[j] = PresignRound3Broadcast(
                    ssid = ssid,
                    from = id,
                    to = j,
                    chiShare = chiShare,
                    deltaShare = deltaShare,
                    bigDeltaShare = bigDeltaShare,
                    gamma = bigGamma,
                    elogProof = elogProof
                )
            }
        }

        return Quintuple(result, chiShare, deltaShare, bigDeltaShare, bigGamma)
    }

    /**
     * Verifies the output of the second round of the presigning process for a given signer.
     *
     * @param j The identifier of the signer whose output is being verified.
     * @param presignRound2Broadcast The broadcast from the second round for the given signer.
     * @param k_i The Paillier ciphertext for K.
     * @param ecdsa_j The ECDSA point for the signer.
     * @param bigGammaShareJ The broadcasted bigGammaShare by peer.
     * @param Bj1 The first public point for El-Gamal encryption of peer's bigGammaShare.
     * @param Bj2 The second public point for El-Gamal encryption of peer's bigGammaShare
     * @param Yj The public point for verification of the zero knowledge proof of bigGammaShare.
     * @return True if the verification is successful; otherwise, false.
     */
    internal fun verifyPresignRound2Broadcast(
        j : Int,
        presignRound2Broadcast : PresignRound2Broadcast,
        k_i : PaillierCipherText,
        ecdsa_j: Point,
        bigGammaShareJ: Point,
        Bj1: Point,
        Bj2: Point,
        Yj: Point
    ) : Boolean {
        // Check ssid.
        if (!this.ssid.contentEquals(presignRound2Broadcast.ssid)) {
            throw PresignException("unknown ssid ${presignRound2Broadcast.ssid}")
        }

        // Check identifier.
        if (j == id || presignRound2Broadcast.from != j || id != presignRound2Broadcast.to ) {
            throw PresignException("invalid id from ${presignRound2Broadcast.from} to ${presignRound2Broadcast.to} ")
        }


        // Verify M(vrfy, Πaff-g_i ,(ssid, j),(Iε,Jε, Di,j , Ki, Fj,i, Γj ), ψi,j ) = 1.
        val deltaPublic = AffgPublic(
            C = k_i.clone(),
            D = presignRound2Broadcast.deltaD,
            Y = presignRound2Broadcast.deltaF,
            X = presignRound2Broadcast.bigGammaShare,
            n1 = publicPrecomps[j]!!.paillierPublic,
            n0 = publicPrecomps[id]!!.paillierPublic,
            aux = publicPrecomps[id]!!.aux
        )
        if (!presignRound2Broadcast.deltaProof.verify(presignRound2Broadcast.from, deltaPublic)) {
            throw PresignException("failed to verify zk proof delta from ${presignRound2Broadcast.from} to ${presignRound2Broadcast.to}")
        }

        // Verify M(vrfy, Πaff-g_i,(ssid, j),(Iε,Jε, Dˆk,j , Ki, Fˆj,i, Xj ), ψˆi,j ) = 1
        val chiPublic = AffgPublic(
            C = k_i.clone(),
            D = presignRound2Broadcast.chiD,
            Y = presignRound2Broadcast.chiF,
            X = ecdsa_j,
            n1 = publicPrecomps[j]!!.paillierPublic,
            n0= publicPrecomps[id]!!.paillierPublic,
            aux = publicPrecomps[id]!!.aux
        )
        if (!presignRound2Broadcast.chiProof.verify(presignRound2Broadcast.from, chiPublic)) {
            throw PresignException("failed to verify zk proof chi from ${presignRound2Broadcast.from} to ${presignRound2Broadcast.to}")
        }

        // Verify M(vrfy, Πelog ,(epid, j),(Γj , g, Bj,1, Bj,2, Yj ), ψj ) = 1.
        val logPublic = ElogPublic(
            L = Bj1,
            M = Bj2,
            X = Yj,
            Y = bigGammaShareJ,
            h = newBasePoint(),
        )
        return presignRound2Broadcast.elogProof.verify(presignRound2Broadcast.from, logPublic)
    }

}

