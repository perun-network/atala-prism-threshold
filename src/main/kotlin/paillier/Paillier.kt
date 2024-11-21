package perun_network.ecdsa_threshold.paillier

import perun_network.ecdsa_threshold.math.*
import perun_network.ecdsa_threshold.pedersen.PedersenParameters
import java.math.BigInteger

/**
 * Represents the public key in the Paillier cryptosystem.
 *
 * @property n The modulus, calculated as n = p * q, where p and q are prime factors.
 * @property nSquared The square of the modulus, calculated as n².
 * @property nPlusOne The value of n + 1.
 */
class PaillierPublic (
    val n: BigInteger,
    val nSquared: BigInteger,
    private val nPlusOne: BigInteger
) {
    companion object {
        /**
         * Creates a new instance of [PaillierPublic] using the specified modulus n.
         *
         * @param n The modulus to be used for the public key.
         * @return A new instance of [PaillierPublic].
         */
        fun newPublicKey(n: BigInteger): PaillierPublic {
            return PaillierPublic(n, n.multiply(n), n.add(BigInteger.ONE))
        }
    }

    /**
     * Encrypts a message using a randomly generated nonce.
     *
     * The encryption is done as:
     * ct = (1 + N)ᵐ * ρⁿ (mod N²).
     *
     * @param m The plaintext message to encrypt.
     * @return A pair consisting of the resulting [PaillierCipherText] and the used nonce.
     */
    fun encryptRandom(m: BigInteger): Pair<PaillierCipherText, BigInteger> {
        val nonce = sampleModNStar(n)
        return Pair(encryptWithNonce(m, nonce), nonce)
    }

    /**
     * Encrypts a message using a specified nonce.
     *
     * The encryption is done as:
     * ct = (1 + N)ᵐ * ρⁿ (mod N²).
     *
     * @param m The plaintext message to encrypt.
     * @param nonce The nonce used for encryption.
     * @return The resulting [PaillierCipherText].
     */
    fun encryptWithNonce(m: BigInteger, nonce: BigInteger): PaillierCipherText {
        val mAbs = m.abs()
        val nHalf = n.shiftRight(1)

        if (mAbs > nHalf) {
            throw IllegalArgumentException("Encrypt: tried to encrypt message outside of range [-(N-1)/2, …, (N-1)/2]")
        }

        val c = nPlusOne.mod(nSquared).modPow(m, nSquared)
        val rhoN = nonce.mod(nSquared).modPow(n, nSquared)

        return PaillierCipherText(c.mod(nSquared).multiply(rhoN.mod(nSquared)).mod(nSquared))
    }

    /**
     * Compares this instance with another object for equality.
     *
     * @param other The object to compare this instance with.
     * @return `true` if the specified object is a [PaillierPublic] with the same modulus; `false` otherwise.
     */
    override fun equals(other: Any?): Boolean {
        return (other is PaillierPublic) && n.compareTo(other.n) == 0
    }


    /**
     * Validates that the provided ciphertexts are in the correct range and are coprime to N².
     *
     * @param cts The ciphertexts to validate.
     * @return `true` if all ciphertexts are valid; `false` otherwise.
     */
    fun validateCiphertexts(vararg cts: PaillierCipherText): Boolean {
        for (ct in cts) {
            if (!ct.c.gcd(nSquared).equals(BigInteger.ONE) ) return false
        }
        return true
    }

    fun toByteArray(): ByteArray {
        // Convert each BigInteger to its byte array representation
        val nBytes = n.toByteArray()
        val nSquaredBytes = nSquared.toByteArray()
        val nPlusOneBytes = nPlusOne.toByteArray()

        // Helper function to convert an integer size to a 4-byte array
        fun Int.toByteArray(): ByteArray = byteArrayOf(
            (this shr 24).toByte(),
            (this shr 16).toByte(),
            (this shr 8).toByte(),
            this.toByte()
        )

        // Combine the lengths and the actual byte arrays
        return nBytes.size.toByteArray() + nBytes +
                nSquaredBytes.size.toByteArray() + nSquaredBytes +
                nPlusOneBytes.size.toByteArray() + nPlusOneBytes
    }
}

/**
 * Validates the modulus N to ensure it is appropriate for use in the Paillier scheme.
 *
 * The validation checks:
 * - log₂(n) should equal the expected bit length (BitsPaillier).
 * - n must be odd.
 *
 * @param n The modulus to validate.
 * @return An [Exception] if validation fails; otherwise, returns null.
 */
fun validateN(n: BigInteger): Exception? {
    if (n.signum() <= 0) return IllegalArgumentException("modulus N is nil")
    if (n.bitLength() != BitsPaillier) {
        return IllegalArgumentException("Expected bit length: $BitsPaillier, found: ${n.bitLength()}")
    }
    if (!n.testBit(0)) return IllegalArgumentException("Modulus N is even")

    return null
}


/** Paillier's Secret Key **/
// Define errors for prime validation
val ErrPrimeBadLength = IllegalArgumentException("Prime factor is not the right length")
val ErrNotBlum = IllegalArgumentException("Prime factor is not equivalent to 3 (mod 4)")
val ErrNotSafePrime = IllegalArgumentException("Supposed prime factor is not a safe prime")

/**
 * Represents the secret key in the Paillier cryptosystem.
 *
 * @property p One of the prime factors used to generate the key.
 * @property q The other prime factor used to generate the key.
 * @property phi The value of φ(n) = (p-1)(q-1).
 * @property phiInv The modular inverse of φ(n) mod n.
 * @property publicKey The corresponding public key.
 */
data class PaillierSecret(
    val p: BigInteger,
    val q: BigInteger,
    val phi: BigInteger,
    val phiInv: BigInteger,
    val publicKey: PaillierPublic
) {
    /**
     * Decrypts a ciphertext and returns the plaintext message.
     *
     * @param ct The ciphertext to decrypt.
     * @return The plaintext message as a [BigInteger].
     * @throws IllegalArgumentException If the ciphertext is invalid.
     */
    fun decrypt(ct: PaillierCipherText): BigInteger {
        val n = publicKey.n
        val one = BigInteger.ONE

        if (!publicKey.validateCiphertexts(ct)) {
            throw IllegalArgumentException("paillier: failed to decrypt invalid ciphertext")
        }

        // r = c^Phi (mod N²)
        var result = ct.c.modPow(phi, publicKey.nSquared)

        // r = c^Phi - 1
        result = result.subtract(one)

        // r = [(c^Phi - 1) / N]
        result = result.divide(n)

        // r = [(c^Phi - 1) / N] * Phi⁻¹ (mod N)
        result = result.multiply(phiInv).mod(n)

        // Set symmetric if needed
        return result.toModSymmetric(n)
    }

    /**
     * Extension function to convert a value to its symmetric modulo representation in the range ±(N-2)/2.
     *
     * @param n The modulus to use for the symmetric representation.
     * @return The symmetric modulo value as a [BigInteger].
     */
    private fun BigInteger.toModSymmetric(n: BigInteger): BigInteger {
        val halfN = n.subtract(BigInteger.TWO).divide(BigInteger.TWO)
        return if (this > halfN) this.subtract(n) else this
    }

    /**
     * Decrypts a ciphertext and returns the plaintext message along with the randomness used.
     *
     * @param ct The ciphertext to decrypt.
     * @return A pair consisting of the plaintext message and the randomness used during encryption.
     */
    fun decryptRandom(ct: PaillierCipherText): Pair<BigInteger, BigInteger> {
        val m = decrypt(ct)
        val mNeg = m.negate()

        // x = C(N+1)⁻ᵐ (mod N)
        val n = publicKey.n
        val x = publicKey.n.modPow(mNeg, n).multiply(ct.c).mod(n)

        // r = xⁿ⁻¹ (mod N)
        val nInverse = phi.modInverse(n)
        val r = x.modPow(nInverse, n)

        return m to r
    }

    /**
     * Generates parameters for a Pedersen commitment.
     *
     * @return A pair consisting of [PedersenParameters] and a lambda value.
     */
    fun generatePedersenParameters(): Pair<PedersenParameters, BigInteger> {
        val n = publicKey.n
        val (s, t, lambda) = samplePedersen(phi, publicKey.n)
        val ped = PedersenParameters(n, s, t)
        return ped to lambda
    }
}

/**
 * Generates a new PublicKey and its associated SecretKey for the Paillier cryptosystem.
 *
 * @return A pair consisting of a new [PaillierPublic] and its corresponding [PaillierSecret].
 */
fun paillierKeyGen(): Pair<PaillierPublic, PaillierSecret> {
    val sk = newPaillierSecret()
    return sk.publicKey to sk
}


/**
 * Generates a new SecretKey for the Paillier cryptosystem by generating suitable primes p and q.
 *
 * @return A new instance of [PaillierSecret].
 * @throws IllegalArgumentException If the generated primes are not valid.
 */
fun newPaillierSecret(): PaillierSecret {
    val (p, q) = generatePaillierBlumPrimes()
    return newPaillierSecretFromPrimes(p, q)
}


/**
 * Generates a new SecretKey from given prime factors p and q. (N = p*q)
 *
 * @param p One prime factor.
 * @param q The other prime factor.
 * @return A new instance of [PaillierSecret].
 * @throws IllegalArgumentException If the provided primes are not suitable for the Paillier scheme.
 */
fun newPaillierSecretFromPrimes(p: BigInteger, q: BigInteger): PaillierSecret {
    val one = BigInteger.ONE

    if (!validatePrime(p) || !validatePrime(q)) {
        throw IllegalArgumentException("Paillier prime not valid")
    }

    val n = p.multiply(q)
    val nSquared = n.multiply(n)
    val nPlusOne = n.add(one)

    val pMinus1 = p.subtract(one)
    val qMinus1 = q.subtract(one)
    val phi = pMinus1.multiply(qMinus1)
    val phiInv = phi.modInverse(n)

    return PaillierSecret(
        p = p,
        q = q,
        phi = phi,
        phiInv = phiInv,
        publicKey = PaillierPublic(n, nSquared, nPlusOne)
    )
}

/**
 * Validates whether the provided prime p is suitable for use in the Paillier cryptosystem.
 *
 * The validation checks:
 * - The bit length of p must equal the expected bit length for Blum primes.
 * - p must be equivalent to 3 (mod 4).
 * - (p-1)/2 must be prime.
 *
 * @param p The prime number to validate.
 * @return `true` if p is a suitable prime; `false` otherwise.
 * @throws IllegalArgumentException If the prime does not meet the validation criteria.
 */
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

    if (!pMinus1Div2.isProbablePrime(2)) {
        throw ErrNotSafePrime
    }

    return true
}
