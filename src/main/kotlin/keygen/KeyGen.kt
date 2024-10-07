package perun_network.ecdsa_threshold.keygen

import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.ecdsa.PublicKey
import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.ecdsa.newPoint
import perun_network.ecdsa_threshold.keygen.shamir.lagrange
import perun_network.ecdsa_threshold.keygen.shamir.lagrangeOf
import perun_network.ecdsa_threshold.keygen.shamir.sampleEcdsaShare
import perun_network.ecdsa_threshold.paillier.PaillierPublic
import perun_network.ecdsa_threshold.paillier.PaillierSecret
import perun_network.ecdsa_threshold.paillier.paillierKeyGen
import perun_network.ecdsa_threshold.pedersen.PedersenParameters
import java.security.MessageDigest
import java.security.SecureRandom
import kotlin.random.Random
import kotlin.reflect.jvm.internal.impl.descriptors.Visibilities.Public

class SecretPrecomputation(
    val id : Int,
    val ssid: ByteArray,
    val threshold: Int,
    val ecdsaShare: Scalar,
    val paillierSecret: PaillierSecret,
)

class PublicPrecomputation (
    val id : Int,
    val ssid: ByteArray,
    val publicEcdsa: Point,
    val paillierPublic : PaillierPublic,
    val aux: PedersenParameters
)

fun generateSessionId(byteSize: Int = 16): ByteArray {
    val randomBytes = ByteArray(byteSize)
    val secureRandom = SecureRandom()
    secureRandom.nextBytes(randomBytes)

    val sha256Digest = MessageDigest.getInstance("SHA-256")
    val hashedBytes = sha256Digest.digest(randomBytes)

    return hashedBytes.copyOf(byteSize)
}


fun generatePrecomputations(n: Int, t: Int, idRange: Int) : Triple<List<Int>, Map<Int, SecretPrecomputation>, Map<Int, PublicPrecomputation>> {
    if (idRange < n ) throw IllegalArgumentException("id must be higher than n")
    val ids = generatePartyIds(n, idRange)
    println("Parties: $ids")
    val ssid = generateSessionId()
    val precomps = mutableMapOf<Int, SecretPrecomputation>()
    val publics = mutableMapOf<Int, PublicPrecomputation>()

    // generate threshold precomputations
    val (secretShares, publicShares) = sampleEcdsaShare(t, ids)
    for (i in ids) {
            val (paillierPublic, paillierSecret) = paillierKeyGen()
            val (aux, _) = paillierSecret.generatePedersen()

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
            publics[i] = publicPrecomp
            precomps[i] = secretPrecomputation
        println("Finished precomputation for $i")
    }

    return Triple(ids ,  precomps , publics)
}

fun publicKeyFromShares(signers : List<Int>, publicShares : Map<Int, PublicPrecomputation>) : PublicKey {
    var sum = newPoint()
    val lagrangeCoeffs = lagrange(signers)
    for (i in signers) {
        sum = sum.add(lagrangeCoeffs[i]!!.act(publicShares[i]!!.publicEcdsa))
    }
    return sum.toPublicKey()
}

// ScalePrecomputation will scale the publc and private Shares of signers with Lagrange's coefficients.
fun scalePrecomputations(signers : List<Int>, precomps : Map<Int, SecretPrecomputation>, publics : Map<Int, PublicPrecomputation>)
: Triple<MutableMap<Int, SecretPrecomputation>, MutableMap<Int,PublicPrecomputation>, Point> {
    val lagrangeCoefficients = lagrange(signers)


    // Initialize a map to hold the scaled precomputations
    val scaledPrecomps = mutableMapOf<Int, SecretPrecomputation>()
    val scaledPublics = mutableMapOf<Int, PublicPrecomputation>()

    // Scale secret and public ECDSA Shares
    for (id in signers) {
        val scaledEcdsaShare = lagrangeCoefficients[id]!!.multiply(precomps[id]!!.ecdsaShare)

        val scaledPublicShare = lagrangeCoefficients[id]!!.act(publics[id]!!.publicEcdsa)

        scaledPublics[id] = PublicPrecomputation(
            id = id,
            ssid = precomps[id]!!.ssid,
            publicEcdsa = scaledPublicShare,
            paillierPublic = publics[id]!!.paillierPublic,
            aux = publics[id]!!.aux
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

fun generatePartyIds(n: Int, idRange: Int): List<Int> {
    if (n > idRange)  throw IllegalArgumentException("Cannot generate $n distinct numbers in the range [1, 100]")
    return (1.. idRange).shuffled().take(n)
}