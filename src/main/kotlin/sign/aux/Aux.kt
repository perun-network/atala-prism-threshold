package perun_network.ecdsa_threshold.sign.aux

import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.ecdsa.Scalar.Companion.scalarFromInt
import perun_network.ecdsa_threshold.keygen.PublicPrecomputation
import perun_network.ecdsa_threshold.keygen.SecretPrecomputation
import perun_network.ecdsa_threshold.math.SEC_BYTES
import perun_network.ecdsa_threshold.math.sampleRID
import perun_network.ecdsa_threshold.math.shamir.ExponentPolynomial
import perun_network.ecdsa_threshold.math.shamir.Polynomial
import perun_network.ecdsa_threshold.math.shamir.Polynomial.Companion.newPolynomial
import perun_network.ecdsa_threshold.math.shamir.sum
import perun_network.ecdsa_threshold.paillier.PaillierPublic
import perun_network.ecdsa_threshold.paillier.PaillierSecret
import perun_network.ecdsa_threshold.paillier.paillierKeyGenMock
import perun_network.ecdsa_threshold.pedersen.PedersenParameters
import perun_network.ecdsa_threshold.zero_knowledge.FacPrivate
import perun_network.ecdsa_threshold.zero_knowledge.FacProof
import perun_network.ecdsa_threshold.zero_knowledge.FacPublic
import perun_network.ecdsa_threshold.zero_knowledge.ModPrivate
import perun_network.ecdsa_threshold.zero_knowledge.ModProof
import perun_network.ecdsa_threshold.zero_knowledge.ModPublic
import perun_network.ecdsa_threshold.zero_knowledge.PrmPrivate
import perun_network.ecdsa_threshold.zero_knowledge.PrmProof
import perun_network.ecdsa_threshold.zero_knowledge.PrmPublic
import perun_network.ecdsa_threshold.zero_knowledge.SchnorrCommitment
import perun_network.ecdsa_threshold.zero_knowledge.SchnorrPrivate
import perun_network.ecdsa_threshold.zero_knowledge.SchnorrProof
import perun_network.ecdsa_threshold.zero_knowledge.SchnorrPublic
import java.math.BigInteger
import java.security.MessageDigest

/**
 * This class handles the auxiliary information for the threshold ECDSA signature generation,
 * including key generation, polynomial management, cryptographic proofs, and communication
 * between the parties in a multi-party signing protocol.
 *
 * @param ssid Session identifier used for the specific signing session.
 * @param id The identifier of the current party (signer).
 * @param threshold The threshold number of parties required to sign.
 * @param previousShare The share of the previous round's secret, if applicable.
 * @param previousPublic The public points from the previous round, if applicable.
 * @param selfPolynomial The polynomial for the current party in the Shamir secret sharing.
 * @param selfExpPolynomial The exponent polynomial used in the protocol.
 * @param selfShare The share of the secret for the current party.
 * @param rid The random identifier of the current iteration of precomputations.
 * @param uShare The u_i value used in the Aux-Info protocol.
 * @param paillierSecret The Paillier secret key for encryption.
 * @param paillierPublic The Paillier public key for encryption.
 * @param pedersenLambda The lambda value for the Pedersen commitment.
 * @param pedersenPublic The public parameters for the Pedersen commitment.
 * @param prmProof The proof for the Pedersen commitment.
 * @param schnorrCommitments The Schnorr commitments for each party.
 * @param As The set of public points associated with each Schnorr commitment.
 */
class Aux (
    val ssid: ByteArray,
    val id: Int,
    val threshold: Int,

    private val previousShare : Scalar?,
    private val previousPublic: Map<Int, Point>?,

    private var selfPolynomial : Polynomial? = null,
    var selfExpPolynomial: ExponentPolynomial? = null,
    private var selfShare: Scalar? = null,

    var rid: ByteArray? = null,
    var uShare: ByteArray? = null,

    private var paillierSecret: PaillierSecret? = null,
    var paillierPublic: PaillierPublic? = null,
    private var pedersenLambda: BigInteger? = null,
    var pedersenPublic: PedersenParameters? = null,
    var prmProof : PrmProof? = null,

    private var schnorrCommitments: Map<Int, SchnorrCommitment>? = null,
    var As : Map<Int, Point>? = null
) {
    /**
     * Executes the first round of the auxiliary protocol.
     * In this round, Paillier and Pedersen parameters are sampled, a new polynomial is created,
     * and Schnorr commitments are made.
     *
     * @param parties A list of party identifiers involved in the protocol.
     * @return A map of broadcasts to be sent to each party containing necessary information.
     */
    fun auxRound1(parties: List<Int>) : Map<Int, AuxRound1Broadcast> {
        // sample Paillier and Pedersen
        val (paillierPublic, paillierSecret) = paillierKeyGenMock()
        val (publicPedersen, secretLambda) = paillierSecret.generatePedersenParameters()

        // Compute ψi = M(prove, Πprm,(sid, i),(Nˆi, si, ti); λi).
        val prmProof = PrmProof.newProof(id, PrmPublic(publicPedersen), PrmPrivate(paillierSecret.phi, secretLambda))

        // Sample new polynomial
        val polynomial = newPolynomial(threshold)

        val ePoly = polynomial.exponentPolynomial()
        val selfShare = polynomial.eval(scalarFromInt(id))

        // Schnorr Commitment
        val schnorrCommitments = mutableMapOf<Int, SchnorrCommitment>()
        val As = mutableMapOf<Int, Point>()
        for (j in parties) {
            schnorrCommitments[j] = SchnorrCommitment.newCommitment()
            As[j] = schnorrCommitments[j]!!.A
        }

        // Sample u_i, rid_i
        val rid = sampleRID()
        val uShare = sampleRID()
        val hash = hash(ssid, id, ePoly, As, paillierPublic, publicPedersen)

        this.selfPolynomial = polynomial
        this.selfExpPolynomial = ePoly
        this.selfShare = selfShare
        this.rid = rid
        this.uShare = uShare
        this.paillierPublic = paillierPublic
        this.paillierSecret = paillierSecret
        this.pedersenLambda = secretLambda
        this.pedersenPublic = publicPedersen
        this.prmProof = prmProof
        this.schnorrCommitments = schnorrCommitments
        this.As = As

        val broadcasts = mutableMapOf<Int, AuxRound1Broadcast>()
        for (i in parties) {
            if (i != id) {
                broadcasts[i] = AuxRound1Broadcast(
                    ssid = ssid,
                    from = id,
                    to = i,
                    VHash = hash
                )
            }
        }

        return broadcasts
    }

    /**
     * Executes the second round of the auxiliary protocol.
     * In this round, shares and cryptographic commitments are broadcast to the other parties.
     *
     * @param parties A list of party identifiers involved in the protocol.
     * @return A map of broadcasts containing shares and commitments to be sent.
     */
    fun auxRound2(parties: List<Int>) : Map<Int, AuxRound2Broadcast> {
        val broadcasts = mutableMapOf<Int, AuxRound2Broadcast>()

        for (j in parties) {
            if (j != id) {
                broadcasts[j] = AuxRound2Broadcast(
                    ssid = ssid,
                    from = id,
                    to = j,
                    ePolyShare = selfExpPolynomial!!,
                    As = As!!,
                    paillierPublic = paillierPublic!!,
                    pedersenPublic = pedersenPublic!!,
                    rid = rid!!,
                    uShare = uShare!!,
                    prmProof = prmProof!!
                )
            }
        }

        return broadcasts
    }

    /**
     * Executes the third round of the auxiliary protocol.
     * This round verifies the second-round broadcasts, computes the final signatures,
     * and generates the necessary proofs for each party.
     *
     * @param parties A list of party identifiers involved in the protocol.
     * @param round1Broadcasts The broadcasts from the first round.
     * @param round2Broadcasts The broadcasts from the second round.
     * @return A map of broadcasts containing the final cryptographic proofs and encrypted shares.
     */
    fun auxRound3(
        parties: List<Int>,
        round1Broadcasts: Map<Int, AuxRound1Broadcast>,
        round2Broadcasts:Map<Int, AuxRound2Broadcast>
    ) : Map<Int, AuxRound3Broadcast> {
        // Verify round2 broadcasts
        for (party in parties) {
            if (party != id) {
                if (!round2Broadcasts.containsKey(party) || !round1Broadcasts.containsKey(party)) {
                    throw AuxException("broacasts missing key $party")
                }
                val round2Broadcast = round2Broadcasts[party]
                val round1Broadcast = round1Broadcasts[party]

                if (!round2Broadcast!!.ssid.contentEquals(ssid) || !round1Broadcast!!.ssid.contentEquals(ssid)) {
                    throw AuxException("mismatch ssid for key $party of signer $id")
                }

                if (round2Broadcast.from != party || round1Broadcast.from != party) {
                    throw AuxException("sender's id mismatch for key $party of signer $id")
                }

                if (round2Broadcast.to != id || round1Broadcast.to != id)  {
                    throw AuxException("receiver's id mismatch for key $party of signer $id")
                }

                // Check RID lengths
                if (round2Broadcast.uShare.size != SEC_BYTES || round2Broadcast.rid.size != SEC_BYTES) {
                    throw AuxException("invalid rid length of broadcast from $party to $id")
                }

                // Verify ZK-PRM Proof
                if (!round2Broadcast.prmProof.verify(party, PrmPublic(round2Broadcast.pedersenPublic))) {
                    throw AuxException("invalid prmProof for key $party of signer $id")
                }

                // Check hash
                val hash = hash(
                    ssid, party, round2Broadcast.ePolyShare, round2Broadcast.As, round2Broadcast.paillierPublic,
                    round2Broadcast.pedersenPublic,
                )
                if (!round1Broadcast.VHash.contentEquals(hash)) {
                    throw AuxException("vHash mismatch for key $party of signer $id")
                }
            }
        }

        // RID = ⊕ⱼ RIDⱼ
        var rid = this.rid!!
        for (party in parties) {
            if (party == id) continue
            rid = xorByteArrays(rid, round2Broadcasts[party]!!.rid)
        }

        this.rid = rid

        // Prove N is a blum prime with zkmod
        val modProof = ModProof.newProof(id, rid, ModPublic(paillierPublic!!.n), ModPrivate(paillierSecret!!.p, paillierSecret!!.q, paillierSecret!!.phi))

        // Prove Schnorr's commitment consistency.
        val schProofs = mutableMapOf<Int, SchnorrProof>()
        for (j in parties) {
            val jScalar = scalarFromInt(j)
            val x_j = selfPolynomial!!.eval(jScalar)
            val X_j = x_j.actOnBase()

            schProofs[j] = SchnorrProof.newProofWithCommitment(id, rid, SchnorrPublic(X_j), SchnorrPrivate(x_j), schnorrCommitments!![j]!!)
        }

        val broadcasts = mutableMapOf<Int, AuxRound3Broadcast>()
        for (j in parties) {
            if (j != id) {
                // Prove that the factors of N are relatively large
                val facProof = FacProof.newProof(id, rid, FacPublic(paillierPublic!!.n, round2Broadcasts[j]!!.pedersenPublic),
                    FacPrivate(paillierSecret!!.p, paillierSecret!!.q)
                )

                // compute fᵢ(j)
                val share =  selfPolynomial!!.eval(scalarFromInt(j))
                // Encrypt share
                val (C,_) = round2Broadcasts[j]!!.paillierPublic.encryptRandom(share.value)

                broadcasts[j] = AuxRound3Broadcast(
                    ssid = ssid,
                    from = id,
                    to = j,
                    modProof = modProof,
                    facProof = facProof,
                    schProofs = schProofs,
                    CShare = C,
                )
            }
        }

        return broadcasts
    }

    /**
     * Finalizes the auxiliary protocol by verifying all broadcasts, combining the shares
     * from the other parties, and generating the final secret and public precomputations.
     *
     * @param parties A list of party identifiers involved in the protocol.
     * @param round2Broadcasts The broadcasts from the second round.
     * @param round3Broadcasts The broadcasts from the third round.
     * @return A pair consisting of the final secret precomputation and a map of public precomputations.
     */
    fun auxOutput(
        parties: List<Int>,
        round2Broadcasts: Map<Int, AuxRound2Broadcast>,
        round3Broadcasts: Map<Int, AuxRound3Broadcast>
        ) : Pair<SecretPrecomputation, Map<Int,PublicPrecomputation>> {
        val shareReceiveds = mutableMapOf<Int, Scalar>()

        // Verify round3 Broadcasts
        for (party in parties) {
            if (party == id) continue
            if (!round3Broadcasts.containsKey(party) || !round2Broadcasts.containsKey(party)) {
                throw AuxException("broacasts missing key $party")
            }
            val round3Broadcast = round3Broadcasts[party]
            val round2Broadcast = round2Broadcasts[party]

            if (!round2Broadcast!!.ssid.contentEquals(ssid) || !round3Broadcast!!.ssid.contentEquals(ssid)) {
                throw AuxException("mismatch ssid for key $party of signer $id")
            }

            if (round2Broadcast.from != party || round3Broadcast.from != party) {
                throw AuxException("sender's id mismatch for key $party of signer $id")
            }

            if (round2Broadcast.to != id || round3Broadcast.to != id)  {
                throw AuxException("receiver's id mismatch for key $party of signer $id")
            }

            // Validate Ciphertext C Share
            if (!round2Broadcast.paillierPublic.validateCiphertexts(round3Broadcast.CShare)) {
                throw AuxException("paillier public key cannot verify cipher text $party of signer $id")
            }

            // Decrypt share and verify with polynomial
            val decryptedShare = Scalar.scalarFromBigInteger(paillierSecret!!.decrypt(round3Broadcast.CShare))
            val expectedPublicShare = round2Broadcast.ePolyShare.eval(scalarFromInt(id))
            // X == Fⱼ(i)
            if (expectedPublicShare != decryptedShare.actOnBase()) {
                throw AuxException("failed to validate ECDSA Share of $party with signer $id")
            }

            // Check ZK ModProof and FacProof
            if (!round3Broadcast.modProof.verify(party, rid!!, ModPublic(round2Broadcast.paillierPublic.n))) {
                throw AuxException("Mod ZK verification failed for key $party to signer $id")
            }

            if (!round3Broadcast.facProof.verify(party, rid!!, FacPublic(round2Broadcast.pedersenPublic.n, pedersenPublic!!))) {
                throw AuxException("Fac ZK verification failed for key $party of signer $id")
            }

            // Check all Schnorr's proofs
            for (j in parties) {
                val jScalar = scalarFromInt(j)
                if (!round3Broadcast.schProofs[j]!!.verify(party, rid!!, SchnorrPublic(round2Broadcast.ePolyShare.eval(jScalar)))) {
                    throw AuxException("Schnorr Proof ZK verification failed for key $party at index $j of signer $id")
                }
            }

            shareReceiveds[party] = decryptedShare
        }

        // Calculate the new secret/ public shares
        var secretECDSA = selfShare!!
        val publicECDSA = mutableMapOf<Int, Point>()
        val shamirPolynomials = mutableListOf<ExponentPolynomial>()
        shamirPolynomials.add(this.selfExpPolynomial!!)
        for (party in parties) {
            if (party == id) continue
            secretECDSA = secretECDSA.add(shareReceiveds[party]!!)
            shamirPolynomials.add(round2Broadcasts[party]!!.ePolyShare)
        }

        val shamirPublicPolynomial = sum(shamirPolynomials)
        for (party in parties) {
            publicECDSA[party] = shamirPublicPolynomial.eval(scalarFromInt(party))
        }

        if (previousShare != null && previousPublic != null) {
            secretECDSA = secretECDSA.add(previousShare)
            for (party in parties) {
                publicECDSA[party] = publicECDSA[party]!!.add(previousPublic[party]!!)
            }
        }

        // Compute Precomp
        val publicPrecomps = mutableMapOf<Int, PublicPrecomputation>()
        for (party in parties) {
            if (party == id) {
                publicPrecomps[party] = PublicPrecomputation(
                    id = id,
                    ssid = ssid,
                    publicEcdsa = publicECDSA[party]!!,
                    paillierPublic = this.paillierPublic!!,
                    aux = this.pedersenPublic!!
                )
            } else {
                publicPrecomps[party] = PublicPrecomputation(
                    id = party,
                    ssid = ssid,
                    publicEcdsa = publicECDSA[party]!!,
                    paillierPublic = round2Broadcasts[party]!!.paillierPublic,
                    aux = round2Broadcasts[party]!!.pedersenPublic
                )
            }
        }

        // SecretPrecomputation
        val secretPrecomp = SecretPrecomputation(
            id = id,
            ssid = ssid,
            threshold = threshold,
            ecdsaShare = secretECDSA,
            paillierSecret = paillierSecret!!
        )

        return secretPrecomp to publicPrecomps
    }
}

/**
 * Computes a hash of the given inputs using the SHA-256 algorithm.
 *
 * @param ssid Session identifier.
 * @param id The identifier of the current party.
 * @param epoly The exponent polynomial.
 * @param As A map of Schnorr commitments.
 * @param paillierPublic The Paillier public key.
 * @param pedersenPublic The Pedersen public parameters.
 * @return The resulting hash as a byte array.
 */
private fun hash(ssid: ByteArray, id: Int, epoly: ExponentPolynomial, As: Map<Int, Point>, paillierPublic: PaillierPublic, pedersenPublic: PedersenParameters) : ByteArray {
    // Initialize a MessageDigest for SHA-256
    val digest = MessageDigest.getInstance("SHA-256")

    // Update the digest with each input
    digest.update(ssid)
    digest.update(ByteArray(id))
    digest.update(epoly.toByteArray())
    for (a in As.values) {
        digest.update(a.toByteArray())
    }
    digest.update(paillierPublic.toByteArray())
    digest.update(pedersenPublic.toByteArray())

    // Compute and return the hash
    return digest.digest()
}

/**
 * Performs a bitwise XOR operation on two byte arrays.
 *
 * @param a The first byte array.
 * @param b The second byte array.
 * @return A new byte array containing the XORed result.
 * @throws IllegalArgumentException If the byte arrays have different lengths.
 */
private fun xorByteArrays(a: ByteArray, b: ByteArray): ByteArray {
    require(a.size == b.size) { "Byte arrays must have the same length" }
    return ByteArray(a.size) { i -> (a[i].toInt() xor b[i].toInt()).toByte() }
}
