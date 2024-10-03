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

class SecretPrecomputation(
    val id : Int,
    val ssid: ByteArray,
    val threshold: Int,
    val ecdsaShare: Scalar,
    val paillierSecret: PaillierSecret,
    val publics : Map<Int, PublicPrecomputation>
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


fun generatePrecomputations(n: Int, t: Int, idRange: Int) : Pair<List<Int>, Map<Int, SecretPrecomputation>> {
    if (idRange < n ) throw IllegalArgumentException("id must be higher than n")
    val ids = generatePartyIds(n, idRange)
    println(ids)
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
                paillierSecret = paillierSecret,
                publics = publics,
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
        println("finished $i")
        }
    return ids to  precomps
}

fun publicKeyFromShares(signers : List<Int>, publicShares : Map<Int, PublicPrecomputation>) : PublicKey {
    var sum = newPoint()
    val lagrangeCoeffs = lagrange(signers)
    for (i in signers) {
        sum = sum.add(lagrangeCoeffs[i]!!.act(publicShares[i]!!.publicEcdsa))
    }
    return sum.toPublicKey()
}

fun scalePrecomputations(signers : List<Int>, precomps : Map<Int, SecretPrecomputation>) : MutableMap<Int, SecretPrecomputation> {
    val lagrangeCoefficients = lagrange(signers)


    // Initialize a map to hold the scaled precomputations
    val scaledPrecomps = mutableMapOf<Int, SecretPrecomputation>()
    val scaledPublics = mutableMapOf<Int, PublicPrecomputation>()

    // Scale secret and public ECDSA Shares
    for (id in signers) {
        val scaledEcdsaShare = lagrangeCoefficients[id]!!.multiply(precomps[id]!!.ecdsaShare)
        var publicKey = newPoint()
        for (j in signers) {
            val scaledPublicShare = lagrangeCoefficients[j]!!.act(precomps[id]!!.publics[j]!!.publicEcdsa)
            publicKey = publicKey.add(scaledPublicShare)
        }

        scaledPublics[id] = PublicPrecomputation(
            id = id,
            ssid = precomps[id]!!.ssid,
            publicEcdsa = publicKey,
            paillierPublic = precomps[id]!!.publics[id]!!.paillierPublic,
            aux = precomps[id]!!.publics[id]!!.aux
        )

        // Create a new SecretPrecomputation with the scaled private and public shares
        scaledPrecomps[id] = SecretPrecomputation(
            id = id,
            ssid = precomps[id]!!.ssid,
            threshold = precomps[id]!!.threshold,
            ecdsaShare = scaledEcdsaShare,
            paillierSecret = precomps[id]!!.paillierSecret,
            publics = scaledPublics
        )
    }

    return scaledPrecomps
}

fun generatePartyIds(n: Int, idRange: Int): List<Int> {
    if (n > idRange)  throw IllegalArgumentException("Cannot generate $n distinct numbers in the range [1, 100]")
    return (1.. idRange).shuffled().take(n)
}