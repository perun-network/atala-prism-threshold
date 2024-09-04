package perun_network.ecdsa_threshold.protocols.cmp.paillier

import kotlinx.serialization.Serializable
import perun_network.ecdsa_threshold.math.sample.Pedersen
import perun_network.ecdsa_threshold.math.sample.SafePrimeGenerator
import perun_network.ecdsa_threshold.math.sample.SecureRandomInputStream
import java.math.BigInteger
import perun_network.ecdsa_threshold.params.BitsBlumPrime
import perun_network.ecdsa_threshold.protocols.cmp.pedersen.Parameters
import perun_network.ecdsa_threshold.serializers.BigIntegerSerializer
import java.security.SecureRandom

// Define the errors
val ErrPrimeBadLength = IllegalArgumentException("Prime factor is not the right length")
val ErrNotBlum = IllegalArgumentException("Prime factor is not equivalent to 3 (mod 4)")
val ErrNotSafePrime = IllegalArgumentException("Supposed prime factor is not a safe prime")
val ErrPrimeNil = IllegalArgumentException("Prime is nil")

// SecretKey is the secret key corresponding to a Public Paillier Key.
@Serializable
data class SecretKey(
    @Serializable(with = BigIntegerSerializer::class)
    val p: BigInteger,
    @Serializable(with = BigIntegerSerializer::class)
    val q: BigInteger,
    @Serializable(with = BigIntegerSerializer::class)
    val phi: BigInteger,
    @Serializable(with = BigIntegerSerializer::class)
    val phiInv: BigInteger,
    val publicKey: PublicKey
) {
    // P returns the first of the two factors composing this key.
    fun getP() = p

    // Q returns the second of the two factors composing this key.
    fun getQ() = q

    // Phi returns ϕ = (P-1)(Q-1).
    fun getPhi() = phi

    // Decrypts c and returns the plaintext m ∈ ± (N-2)/2.
    @Throws(IllegalArgumentException::class)
    fun decrypt(ct: CipherText): BigInteger {
        val n = publicKey.modulus()
        val one = BigInteger.ONE

        if (!publicKey.validateCiphertexts(ct)) {
            throw IllegalArgumentException("paillier: failed to decrypt invalid ciphertext")
        }

        // r = c^Phi (mod N²)
        var result = ct.c.modPow(phi, publicKey.modulusSquared())

        // r = c^Phi - 1
        result = result.subtract(one)

        // r = [(c^Phi - 1) / N]
        result = result.divide(n)

        // r = [(c^Phi - 1) / N] * Phi⁻¹ (mod N)
        result = result.multiply(phiInv).mod(n)

        // Set symmetric if needed
        return result
    }

    // DecWithRandomness returns the underlying plaintext, as well as the randomness used.
    @Throws(IllegalArgumentException::class)
    fun decryptWithRandomness(ct: CipherText): Pair<BigInteger, BigInteger> {
        val m = decrypt(ct)
        val mNeg = m.negate()

        // x = C(N+1)⁻ᵐ (mod N)
        val n = publicKey.modulus()
        val x = publicKey.modulus().modPow(mNeg, n).multiply(ct.c).mod(n)

        // r = xⁿ⁻¹ (mod N)
        val nInverse = phi.modInverse(n)
        val r = x.modPow(nInverse, n)

        return m to r
    }

    // GeneratePedersen generates parameters for Pedersen commitment.
    fun generatePedersen(): Pair<Parameters, BigInteger> {
        val n = publicKey.modulus()
        val (s, t, lambda) = Pedersen(SecureRandomInputStream(SecureRandom()), phi, publicKey.modulus())
        val ped = Parameters(n, s, t)
        return ped to lambda
    }
}

// Generates a new PublicKey and its associated SecretKey.
fun keyGen(): Pair<PublicKey, SecretKey> {
    val sk = newSecretKey()
    return sk.publicKey to sk
}

// Generates primes p and q suitable for the scheme, and returns the initialized SecretKey.
fun newSecretKey(): SecretKey {
    val (p, q) = SafePrimeGenerator.generatePaillierKeyPair(SecureRandom())
    return newSecretKeyFromPrimes(p!!, q!!)
}

// Generates a new SecretKey from given primes P and Q.
fun newSecretKeyFromPrimes(P: BigInteger, Q: BigInteger): SecretKey {
    val one = BigInteger.ONE

    val n = P.multiply(Q)
    val nSquared = n.multiply(n)
    val nPlusOne = n.add(one)

    val pMinus1 = P.subtract(one)
    val qMinus1 = Q.subtract(one)
    val phi = pMinus1.multiply(qMinus1)
    val phiInv = phi.modInverse(n)

    val pSquared = pMinus1.multiply(P)
    val qSquared = qMinus1.multiply(Q)
    val nSquaredMod = pSquared.multiply(qSquared)

    return SecretKey(
        p = P,
        q = Q,
        phi = phi,
        phiInv = phiInv,
        publicKey = PublicKey(n, nSquared, nPlusOne)
    )
}

// ValidatePrime checks whether p is a suitable prime for Paillier.
fun validatePrime(p: BigInteger): Boolean {
    val bitsWant = BitsBlumPrime

    // Check bit lengths
    if (p.bitLength() != bitsWant) {
        throw ErrPrimeBadLength
    }

    // Check == 3 (mod 4)
    if (p.mod(BigInteger.valueOf(4)).toInt() != 3) {
        throw ErrNotBlum
    }

    // Check (p-1)/2 is prime
    val pMinus1Div2 = p.subtract(BigInteger.ONE).shiftRight(1)

    if (!pMinus1Div2.isProbablePrime()) {
        throw ErrNotSafePrime
    }

    return true
}

// Helper function to check primality
fun BigInteger.isProbablePrime(certainty: Int = 5): Boolean {
    return this.isProbablePrime(certainty)
}
