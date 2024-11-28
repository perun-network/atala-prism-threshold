package perun_network.ecdsa_threshold.sign.keygen

import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.math.sampleRID
import perun_network.ecdsa_threshold.math.sampleScalar
import perun_network.ecdsa_threshold.zero_knowledge.sch.SchnorrCommitment
import perun_network.ecdsa_threshold.zero_knowledge.sch.SchnorrPrivate
import perun_network.ecdsa_threshold.zero_knowledge.sch.SchnorrProof
import perun_network.ecdsa_threshold.zero_knowledge.sch.SchnorrPublic
import java.security.MessageDigest

data class Keygen (
    val ssid: ByteArray,
    val id: Int,

    // KEYGEN ROUND 1
    private var xShare : Scalar? = null, // k_i
    private var XShare : Point? = null, // gamma_i
    private var rhoShare : Scalar? = null,
    private var alphaCommitment : Scalar? = null,
    private var AShare : Point? = null,
    private var uShare: ByteArray? = null,
    private var VShare : ByteArray? = null,

    // KEYGEN ROUND 3
    private var rho : Scalar? = null,
) {
    fun keygenRound1(parties: List<Int>) : Map<Int, KeygenRound1Broadcast> {
        val broadcasts = mutableMapOf<Int, KeygenRound1Broadcast>()


        // Sample x_i, X_i
        val xShare = sampleScalar()
        val publicShare = xShare.actOnBase()

        // – Sample ρi ← {0, 1}κ and compute (Ai, τ ) ← M(com, Πsch).
        val rhoShare = sampleScalar()
        val schnorrCommitment = SchnorrCommitment.newCommitment()

        val uShare = sampleRID()
        val VShare = hash(ssid, id, rhoShare, publicShare, schnorrCommitment.A, uShare)

        for (j in parties) {
            if (j != id) {
                broadcasts[j] = KeygenRound1Broadcast(
                    ssid = ssid,
                    from = id,
                    to = j,
                    VShare = VShare
                )
            }
        }

        this.xShare = xShare
        this.XShare = publicShare
        this.rhoShare = rhoShare
        this.alphaCommitment = schnorrCommitment.alpha
        this.AShare = schnorrCommitment.A
        this.uShare = uShare
        this.VShare = VShare

        return broadcasts
    }

    fun keygenRound2(
        parties: List<Int>,
    ) : Map<Int, KeygenRound2Broadcast> {
        val broadcasts = mutableMapOf<Int, KeygenRound2Broadcast>()
        for (j in parties) {
            if (j != id) {
                broadcasts[j] = KeygenRound2Broadcast(
                    ssid = ssid,
                    from = id,
                    to = j,
                    rhoShare = rhoShare!!,
                    XShare = XShare!!,
                    AShare = AShare!!,
                    uShare = uShare!!
                )
            }
        }

        return broadcasts
    }

    fun keygenRound3(
        parties: List<Int>,
        keygenRound1Broadcasts: Map<Int, KeygenRound1Broadcast>,
        keygenRound2Broadcasts: Map<Int, KeygenRound2Broadcast>,
    ) : Map<Int, KeygenRound3Broadcast> {
        // Validates Round 2 Broadcasts.
        for (j in parties) {
            if (j == id ) continue
            if (!keygenRound1Broadcasts.containsKey(j) || !keygenRound2Broadcasts.containsKey(j)) {
                throw KeygenException("broacasts missing key $j of signer $id")
            }

            if (!keygenRound1Broadcasts[j]!!.ssid.contentEquals(keygenRound2Broadcasts[j]!!.ssid)) {
                throw KeygenException("mismatch ssid for key $j of signer $id")
            }

            if (keygenRound2Broadcasts[j]!!.from != j || keygenRound1Broadcasts[j]!!.from != j) {
                throw KeygenException("sender's id mismatch for key $j of signer $id")
            }

            if (id != keygenRound2Broadcasts[j]!!.to || keygenRound1Broadcasts[j]!!.to != id) {
                throw KeygenException("receiver's id mismatch for key $j of signer $id")
            }

            val hash = hash(keygenRound1Broadcasts[j]!!.ssid, j,
                keygenRound2Broadcasts[j]!!.rhoShare,
                keygenRound2Broadcasts[j]!!.XShare,
                keygenRound2Broadcasts[j]!!.AShare,
                keygenRound2Broadcasts[j]!!.uShare)

            if (!hash.contentEquals(keygenRound1Broadcasts[j]!!.VShare)) {
                throw KeygenException("corrupted V hash for key $j of signer $id")
            }
        }

        // Compute rho, schnorrProof
        val broadcasts = mutableMapOf<Int, KeygenRound3Broadcast>()
        var rho = this.rhoShare!!
        for (j in parties) {
            if (j == id) continue
            rho = rho.add(keygenRound2Broadcasts[j]!!.rhoShare)
        }

        this.rho = rho

        val schnorrProof = SchnorrProof.newProofWithCommitment(id, rho.toByteArray(),
            SchnorrPublic(XShare!!), SchnorrPrivate(xShare!!), SchnorrCommitment(alphaCommitment!!, AShare!!)
        )

        for (j in parties) {
            if (j != id ) {
                broadcasts[j] = KeygenRound3Broadcast(
                    ssid = ssid,
                    from = id,
                    to = j,
                    schnorrProof = schnorrProof
                )
            }
        }

        return broadcasts
    }

    fun keygenOutput(
        parties: List<Int>,
        keygenRound2Broadcasts: Map<Int, KeygenRound2Broadcast>,
        keygenRound3Broadcasts: Map<Int, KeygenRound3Broadcast>,
    ) : Triple<Scalar, Map<Int,Point>, Point> {
        // Validates Round 3 Broadcasts.
        for (j in parties) {
            if (j == id) continue

            if (!keygenRound3Broadcasts.containsKey(j) || !keygenRound2Broadcasts.containsKey(j)) {
                throw KeygenException("broacasts missing key $j of signer $id")
            }

            if (!keygenRound3Broadcasts[j]!!.ssid.contentEquals(ssid) || !keygenRound2Broadcasts[j]!!.ssid.contentEquals(ssid)) {
                throw KeygenException("mismatch ssid for key $j of signer $id")
            }

            if (keygenRound3Broadcasts[j]!!.from != j || keygenRound2Broadcasts[j]!!.from != j) {
                throw KeygenException("sender's id mismatch for key $j of signer $id")
            }

            if (id != keygenRound3Broadcasts[j]!!.to || keygenRound2Broadcasts[j]!!.to != id) {
                throw KeygenException("receiver's id mismatch for key $j of signer $id")
            }

            if (keygenRound2Broadcasts[j]!!.AShare != keygenRound3Broadcasts[j]!!.schnorrProof.A) {
                throw KeygenException("corrupted AShare for key $j of signer $id")
            }

            if (!keygenRound3Broadcasts[j]!!.schnorrProof.verify(j, rho!!.toByteArray(), SchnorrPublic(keygenRound2Broadcasts[j]!!.XShare))) {
                throw KeygenException("corrupted schnorr Proof for key $j of signer $id")
            }
        }

        // Output public point

        val publics = mutableMapOf<Int, Point>()
        var public = XShare!!
        publics[id] = public
        for (j in parties) {
            if (j == id) continue
            publics[j] = keygenRound2Broadcasts[j]!!.XShare
            public = public.add(keygenRound2Broadcasts[j]!!.XShare)
        }

        return Triple(this.xShare!!, publics,  public)
    }
}


private fun hash(ssid: ByteArray, id: Int, rhoShare: Scalar, publicShare: Point, A: Point, uShare: ByteArray) : ByteArray {
    // Initialize a MessageDigest for SHA-256
    val digest = MessageDigest.getInstance("SHA-256")

    // Update the digest with each input
    digest.update(ssid)
    digest.update(ByteArray(id))
    digest.update(rhoShare.toByteArray())
    digest.update(publicShare.toByteArray())
    digest.update(A.toByteArray())
    digest.update(uShare)

    // Compute and return the hash
    return digest.digest()
}