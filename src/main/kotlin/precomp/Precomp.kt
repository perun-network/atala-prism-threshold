package perun_network.ecdsa_threshold.precomp

import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.ecdsa.PublicKey
import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.ecdsa.newPoint
import perun_network.ecdsa_threshold.math.shamir.Polynomial.Companion.newPolynomial
import perun_network.ecdsa_threshold.math.shamir.lagrange
import perun_network.ecdsa_threshold.paillier.*
import perun_network.ecdsa_threshold.pedersen.PedersenParameters
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Class representing secret precomputations for a party in a threshold ECDSA protocol.
 *
 * @property id The ID of the party.
 * @property ssid The session identifier (SSID) as a byte array.
 * @property threshold The threshold for the protocol.
 * @property ecdsaShare The secret ECDSA share for the party.
 * @property paillierSecret The Paillier secret key for the party.
 */
class SecretPrecomputation(
    val id : Int,
    val ssid: ByteArray,
    val threshold: Int,
    val ecdsaShare: Scalar,
    val paillierSecret: PaillierSecret,
)

/**
 * Class representing public precomputations for a party in a threshold ECDSA protocol.
 *
 * @property id The ID of the party.
 * @property ssid The session identifier (SSID) as a byte array.
 * @property publicEcdsa The public ECDSA point corresponding to the party's share.
 * @property paillierPublic The Paillier public key for the party.
 * @property aux Pedersen parameters for the party.
 */
class PublicPrecomputation (
    val id : Int,
    val ssid: ByteArray,
    val publicEcdsa: Point,
    val paillierPublic : PaillierPublic,
    val aux: PedersenParameters
) {
    override fun equals(other: Any?): Boolean {
        if (other !is PublicPrecomputation) return false
        return id == other.id
                && ssid.contentEquals(other.ssid)
                && publicEcdsa == other.publicEcdsa
                && paillierPublic == other.paillierPublic
                && aux == other.aux
    }
}

/**
 * Generates a random session identifier (SSID) of a given byte size, hashed with SHA-256.
 *
 * @param byteSize The size of the session ID in bytes (default is 16 bytes).
 * @return A byte array representing the session ID.
 */
fun generateSessionId(byteSize: Int = 16): ByteArray {
    val randomBytes = ByteArray(byteSize)
    val secureRandom = SecureRandom()
    secureRandom.nextBytes(randomBytes)

    val sha256Digest = MessageDigest.getInstance("SHA-256")
    val hashedBytes = sha256Digest.digest(randomBytes)

    return hashedBytes.copyOf(byteSize)
}

/**
 * Generates secret and public precomputations for a group of parties.
 *
 * @param n The number of parties.
 * @param t The threshold for the protocol.
 * @return A Triple containing the list of party IDs, a map of secret precomputations, and a map of public precomputations.
 * @throws IllegalArgumentException if `idRange` is less than `n`.
 */
fun generatePrecomputations(n: Int, t: Int) : Triple<List<Int>, Map<Int, SecretPrecomputation>, Map<Int, PublicPrecomputation>> {
    require(n >= t, { "threshold must be less than or equals total parties" })
    val ids = generatePartyIds(n)
    val ssid = generateSessionId()
    val precomps = mutableMapOf<Int, SecretPrecomputation>()
    val publicPrecomps = mutableMapOf<Int, PublicPrecomputation>()

    // generate threshold precomputations
    val (secretShares, publicShares) = sampleEcdsaShare(t, ids)
    for (i in ids) {
            val (paillierPublic, paillierSecret) = paillierKeyGen()
            val (aux, _) = paillierSecret.generatePedersenParameters()

            val secretPrecomputation = SecretPrecomputation(
                id = i,
                ssid = ssid,
                threshold = t,
                ecdsaShare = secretShares[i]!!,
                paillierSecret = paillierSecret
            )

            val publicPrecomp = PublicPrecomputation (
                id = i,
                ssid = ssid,
                publicEcdsa = publicShares[i]!!,
                paillierPublic = paillierPublic,
                aux = aux
            )
            publicPrecomps[i] = publicPrecomp
            precomps[i] = secretPrecomputation
    }

    return Triple(ids ,  precomps , publicPrecomps)
}

/**
 * Samples secret and public precomputations for a group of parties from precomputed safe primes.
 *
 * @param n The number of parties.
 * @param t The threshold for the protocol.
 * @return A Triple containing the list of party IDs, a map of secret precomputations, and a map of public precomputations.
 * @throws IllegalArgumentException if `idRange` is less than `n`.
 */
fun getSamplePrecomputations(n: Int, t: Int) : Triple<List<Int>, Map<Int, SecretPrecomputation>, Map<Int, PublicPrecomputation>> {
    if (n > PRECOMPUTED_PRIMES.size) throw IllegalArgumentException("not enough precomputed primes")
    val ids = generatePartyIds(n)
    val ssid = generateSessionId()
    val precomps = mutableMapOf<Int, SecretPrecomputation>()
    val publicPrecomps = mutableMapOf<Int, PublicPrecomputation>()

    // generate threshold precomputations
    val (secretShares, publicShares) = sampleEcdsaShare(t, ids)
    for (i in ids) {
        val paillierSecret = newPaillierSecretFromPrimes(PRECOMPUTED_PRIMES[i-1].first, PRECOMPUTED_PRIMES[i-1].second)
        val paillierPublic = paillierSecret.publicKey
        val (aux, _) = paillierSecret.generatePedersenParameters()

        val secretPrecomputation = SecretPrecomputation(
            id = i,
            ssid = ssid,
            threshold = t,
            ecdsaShare = secretShares[i]!!,
            paillierSecret = paillierSecret
        )

        val publicPrecomp = PublicPrecomputation (
            id = i,
            ssid = ssid,
            publicEcdsa = publicShares[i]!!,
            paillierPublic = paillierPublic,
            aux = aux
        )
        publicPrecomps[i] = publicPrecomp
        precomps[i] = secretPrecomputation
    }

    return Triple(ids ,  precomps , publicPrecomps)
}

/**
 * Computes a public key from the shares of the signers using Lagrange interpolation.
 *
 * @param signers The list of party IDs that are participating.
 * @param publicShares The map of public precomputations for the parties.
 * @return The resulting public key.
 */
fun publicKeyFromShares(signers : List<Int>, publicShares : Map<Int, PublicPrecomputation>) : PublicKey {
    var sum = newPoint()
    val lagrangeCoeffs = lagrange(signers)
    for (i in signers) {
        sum = sum.add(lagrangeCoeffs[i]!!.act(publicShares[i]!!.publicEcdsa))
    }
    return sum.toPublicKey()
}

/**
 * Scales the precomputations for signers using Lagrange's coefficients and computes the combined public point.
 * Scaling in threshold secret sharing ensures that each participant's share is correctly weighted when reconstructing the secret or combining values.
 *
 * @param signers The list of party IDs that are participating.
 * @param precomps The map of secret precomputations for the parties.
 * @param publicPrecomps The map of public precomputations for the parties.
 * @return A Triple containing scaled secret precomputations, scaled public precomputations, and the combined public point.
 */
fun scalePrecomputations(signers : List<Int>, precomps : Map<Int, SecretPrecomputation>, publicPrecomps : Map<Int, PublicPrecomputation>)
: Triple<MutableMap<Int, SecretPrecomputation>, MutableMap<Int, PublicPrecomputation>, Point> {
    val lagrangeCoefficients = lagrange(signers)

    // Initialize a map to hold the scaled precomputations
    val scaledPrecomps = mutableMapOf<Int, SecretPrecomputation>()
    val scaledPublics = mutableMapOf<Int, PublicPrecomputation>()

    // Scale secret and public ECDSA Shares
    for (id in signers) {
        val scaledEcdsaShare = lagrangeCoefficients[id]!!.multiply(precomps[id]!!.ecdsaShare)

        val scaledPublicShare = lagrangeCoefficients[id]!!.act(publicPrecomps[id]!!.publicEcdsa)

        scaledPublics[id] = PublicPrecomputation(
            id = id,
            ssid = precomps[id]!!.ssid,
            publicEcdsa = scaledPublicShare,
            paillierPublic = publicPrecomps[id]!!.paillierPublic,
            aux = publicPrecomps[id]!!.aux
        )

        // Create a new SecretPrecomputation with the scaled private and public shares
        scaledPrecomps[id] = SecretPrecomputation(
            id = id,
            ssid = precomps[id]!!.ssid,
            threshold = precomps[id]!!.threshold,
            ecdsaShare = scaledEcdsaShare,
            paillierSecret = precomps[id]!!.paillierSecret,
        )
    }

    var public = newPoint()
    for (j in signers) {
        public = public.add(scaledPublics[j]!!.publicEcdsa)
    }

    return Triple(scaledPrecomps, scaledPublics, public)
}

/**
 * Generates a list of distinct party IDs from a given range.
 *
 * @param n The number of party IDs to generate.
 * @return A list of unique party IDs.
 * @throws IllegalArgumentException if `n` is greater than `idRange`.
 */
fun generatePartyIds(n: Int): List<Int> {
    return (1.. n).shuffled().take(n)
}

/**
 * Generates secret ECDSA shares and their corresponding public points using Shamir's Secret Sharing scheme.
 *
 * @param threshold The threshold number of shares required to reconstruct the secret.
 * @param ids The list of participant IDs.
 * @return A pair containing the secret shares and their corresponding public points.
 */
fun sampleEcdsaShare(threshold: Int, ids: List<Int>) : Pair<Map<Int, Scalar>, Map<Int, Point>> {
    val secretShares = mutableMapOf<Int, Scalar>()
    val publicShares = mutableMapOf<Int, Point>()
    val polynomial = newPolynomial(threshold)
    for (i in ids) {
        secretShares[i] = (polynomial.eval(Scalar(BigInteger.valueOf(i.toLong()))))
        publicShares[i] = (secretShares[i]!!.actOnBase())
    }

    return secretShares to publicShares
}