package perun_network.ecdsa_threshold.paillier

import perun_network.ecdsa_threshold.math.*
import perun_network.ecdsa_threshold.pedersen.PedersenParameters
import java.math.BigInteger
import kotlin.random.Random


// Precomputed safe Blum prime pairs
val PRECOMPUTED_PRIMES: List<Pair<BigInteger, BigInteger>> = listOf(
    Pair(
        BigInteger("00e8dc0a9a7723c9ba02f5b2375c5922d092e042a5a194c324a7068c3365e982d5f08875dfb85ee7a8eba68e967e0c0040793d26f5ed4e1f4a3ef2244706609b48ecdc00d81dbf11e7ed20eb1da86a626508f22a0bc1b49cf4795e2b19dccc9e6cd7c1bda0e41d71e5531c30f748373757f1ed8966b964286f8fa236b5e1a7b3df", 16), // p1
        BigInteger("00e4e03ba61889000a30da54b29b801e69bd7a4ded27389f4fab57b5a0d0acb00ff45f0187c625425b70cedf0910c14be1d269cd77db016795f4691efe5857d46aa3e43921829e4ce807e765177113b04d7860d5033821ae409a269d086f1a3447bd00103bab2d61a139cf949e0341e2fa38a28fbee4fd2046b95a79884b0bfadf", 16)  // q1
    ),
    Pair(
        BigInteger("0080249672e660f63696820621f012f53cb097a40dc36ba61516face3401d74be0848349b74a496b164339eb56eeae4b9c6b10c9d92c279affe9db02e2928c6b0e0548746f1adb2afd9dbd0faa9c1c580822ae6710ce8692e822a097c7ef1452d44ec628060c044f54cd3f10b9084da4ceccb1c165a7e76517bb2f6809d5f3fe0b", 16), // p2
        BigInteger("00b864ec793381f8ec0230accb20585c0a9398e13796e06924fae416d8c65159c9d19965de84a27ce86d276d77d6ff28e3588e7f19086ebee6697978c57afd6cb9bdb202ff5afe9e3e4c17163f3e5fdceb3e6522cc312e0374bfc8f66818429fc99338626c72aa273f06897c2fb13bd74f652fcb1e08c98f53c271a377457b70bf", 16)  // q2
    ),
    Pair(
        BigInteger("00d6d817faa9ea143ad3b4ad3b067221765673ba63eb0cfbf1bccc2b6502b6d09c787111e03695b038d4bdae051a534116fed9e24458bc9e76368450afd6f4cc9b45124c3de3cb960bdd98c4be22e8eaf02899b8e7c7e644286745f2855821fec0cea484c2ce092f6ac234f6dd0ab6b526687ec2a406d8afd93b8838e7223f2f1f", 16), // p3
        BigInteger("00f0a3a43f62fbd4da1a762df7c407f9fa99d8dfbf5d2e1f12854292ff8ed1c658a2fc1c1719d1f48b5fc3bb420266fd263441cfd354c414fe8abee12cb79f9b45dbfc1cc310ef55cd23793b1e11854288e37763fa21a523a767d0b09d04d6b1cd1eb5f33690798bdb3daaed584b75e72a0a0fc549693faf0e6253f5309c24e407", 16)  // q3
    ),
    Pair(
        BigInteger("00d6a59f9bb8a268e7d09980ac46f4d896a167e53d1c4b64f631ce332a50d24549f2833098d264de70f8515f135097042f8ea986ee22667f5e1ee2ca09ab5b514955a361de6ec101226c712621d114d9ff108ac05ab403dbbe0a9dd8ab3ec641e5d01af2123bfe0c351197c0f70c7762bb9488c3197445177467f470c0d526af23", 16), // p4
        BigInteger("00d30084a00ca2d9666dc2b0a914aed59078f90926dd7ca7f409f32b14e49ca466a9f96d7c4faf85b01b07cb29e268dc37f3dc317f7c82279437794f2d274acdd2541540f62e95bbb1fca2eab3d43a17cda6c099fcd20a97da251df4e0caf03c55c445b8b4d58324b5426d72e8a4a0e2d5d3c25b4cdeb90c597f1ffbca695b737b", 16)  // q4
    ),
    Pair(
        BigInteger("00e35cf40ac7cee41245db61490ad6a93a5a518a888f637fa204bedec976c74e3b61b541fe85f9200951c53eca7d0e0cb54911f5b2a19e48baae4cc9cf39927d574c242d6b0fdfe05aa766d7f45c1a6c76aa6b1b2310a8c9fac0bbae69b120f7c41842f563a93b18b721534423ad8cc90133a511a521933904c7ad7541be8277c3", 16), // p5
        BigInteger("00d9e276b93cb25c891c5e2944c01930f7e30c23dac0c26b2b3745655a3fb1dac760d2f489cccae0920e976aa043d710624951165b078478d4353f8c01e3d15ea3c7d39a4a89f632d67e27128c98d312d20755c7d1aadcc7326cd6954358b0bd6972f26649f7556220880a6a59e1a9347bf7ba235907f23280a7ffd2b19b7148cb", 16)  // q5
    ),
    Pair(
        BigInteger("00e97f56625eb209d583152c843f6905c25e6bea4495df684d8a3eb49d10ebe72a6dd0ce0f22aa0fa58f05b9c013dc0c9bd6d7cfffba38f03d8ec3e86dbecbe76548be186bba9d2f470aa0a497c6ad51d0dee24e42215a2afd793211cb987d7f90d3c1c15716dc70f442db7ea76ef97a94b3e417482f4fef81cd6702981f1202f7", 16), // p6
        BigInteger("00bd6dbc14107371fe387c4634e24e3722a9b7f7b8c971913c71a35f8a7d2f44295dd3541836687191a8d74050745aeb41a4e53ad0d7be2441bd0a4fc213ac21e0a2fc0d65e9d9e1d1e68fd96c5524e818fda6c1fd15eff45ebbc695266a5ef4abc145c02fc4867609afe949026f4f2c841a2e0e5e0d5d635d4c93f4230f7d5b7f", 16)  // q6
    ),
    Pair(
        BigInteger("00e851ddcfe4832be7424cebbb2446586177807ef64aa0f19e3c1dd82ab3d299eebb826c8bc0879fa7abc638e2d7e97520729254cb9e264136288a26e7c98fa74b9a3654db07736a9a7b6a5189d26cd1d81a7bfe5f81a153eb3c9456d2b713d3cb7a2e4c0afd0bc6e1892b35357afd144e80e14201417f550950d17a660842f517", 16), // p7
        BigInteger("00804d0dc1f69cfd8754e718340caf9f7a6ee6472b669ff05de26cb701e7dc9b8df7a2abf1bc1f32256c3d7c81297ccd81edef9c533b3f40afd9ad2fe7af35cb28003912eb2845ba0310b01b275dbcbcaae7d844c9f326243af45acbfaa34562d6784fb6f274c09c65f50e713a5656dddf5171506b60c0b12f37972d3fabc10c6b", 16)  // q7
    ),
    Pair(
        BigInteger("00df72feb91e073a7713792e45883bb9115b097513fd62b336fc04d66ee2426e9d0dfbe2a6b6a078e5bd420caba6a6d9f5fd63b92e2b97b5e68bf8fe35afa4acff2fb1ab1c3bed582a310c99c847c8bd68113f96faca91d0ca294d48808ea41c87f2a131cf7870d31f413c90428fb6f9020570094a347b5b24be2a515f7cedc9a3", 16), // p8
        BigInteger("00bb96cb3bf965bba6b22ebb97eb5cb363ca61934774bcd30a66bb1785c64b9a8ec00427756f6114bed12f4b3314c8c2d4422ac07c094681da7f84d330715ae3cd245c78ed5e1d4d374d5984f304436e8684bf0b0043a0cdfabbe9832901b73c5c78f8594f2987e2d5d48cf481092130d1bcadebb6042a86d3692e3ac121723bb3", 16)  // q8
    ),
    Pair(
        BigInteger("00d5dc4e14b1581867b703155345899b9ac57b5b8dbac181d12f09dd4c4b70e6600a164bc6dbbbafeca0a1b3e93f31a49bf174996b4d1ae8f44a824f1db00627e654aa2b44ba5d843d73a3b3905e0db590d306dc0ab58639aa369ec418785032cc1e5acc2b85abdc3edd00942a22ef9c0c3bf13e888440a04be04185815f21f4cb", 16), // p9
        BigInteger("00c088b648fb8b56ef810f081d62e8426e446e758a817aae463ab2e804e74101d66c8e8a7b2a53c968f717faf7a3b77598a85c7acacab7c3f7428e6769b94130c03cc878b5f3d045f453c836ff4a7986ba9371d2c8d98383a717a004640561f1ae00d66d161da15f8b72ff67be6322b3845bf57a2ae6991181ffac8dc429621f1b", 16)  // q9
    ),
    Pair(
        BigInteger("00e5db3b97eac7e38b2fb674957e9fa377b3e63419c216d392e577763f86048bbe76b3f1f9ec82928052ce16f7ac744856391bcdd339f4d2ebf9925cb116747f3709c8382e14496376ba0bebf7574be7f0af023b042d15e7569e35090d6936efc1b39c6c1c8df033396829bae2c8a617c328f801627f2ffbbac7738e5028fa03e7", 16), // p10
        BigInteger("0097c0909bfdc4e5df81b5533021768a330e41359953a72b39a8219fd68f7e28de383250017b9f1a1c7f45e0ab0ea941f939587d8f659c5aac9ba83d1490b9554828294304446966608b5e6b2e9e108dbbb5d86a4cc2a3d1b07fca79054db382f096021dbd090af25e0046baf583ad31b500f34acaf2c9fb521525cc6f33a9239f", 16)  // q10
    )
)

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

    override fun hashCode(): Int {
        var result = n.hashCode()
        result = 31 * result + nSquared.hashCode()
        result = 31 * result + nPlusOne.hashCode()
        return result
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
    if (n.bitLength() > BitsPaillier) {
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
 * Generates a new PublicKey and its associated SecretKey from a precomputed primesPair for the Paillier cryptosystem.
 *
 * @return A pair consisting of a new [PaillierPublic] and its corresponding [PaillierSecret].
 */
fun paillierKeyGenMock() : Pair<PaillierPublic, PaillierSecret> {
    val id = Random.nextInt(PRECOMPUTED_PRIMES.size)
    val sk = newPaillierSecretFromPrimes(PRECOMPUTED_PRIMES[id].first, PRECOMPUTED_PRIMES[id].second)
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
