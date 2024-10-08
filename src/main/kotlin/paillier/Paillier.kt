package perun_network.ecdsa_threshold.paillier

import perun_network.ecdsa_threshold.math.*
import perun_network.ecdsa_threshold.pedersen.PedersenParameters
import java.math.BigInteger
import java.security.SecureRandom

class PaillierPublic (
    // n = p⋅q
    val n: BigInteger,
    // nSquared = n²
    val nSquared: BigInteger,
    // nPlusOne = n + 1
    private val nPlusOne: BigInteger
) {
    companion object {
        fun newPublicKey(n: BigInteger): PaillierPublic {
            return PaillierPublic(n, n.multiply(n), n.add(BigInteger.ONE))
        }
    }

    fun n(): BigInteger {
        return this.n
    }

    // encryptRandom returns the encryption of m under the public key pk.
    // The nonce used to encrypt is returned.
    // ct = (1+N)ᵐρᴺ (mod N²).
    fun encryptRandom(m: BigInteger): Pair<PaillierCipherText, BigInteger> {
        val nonce = sampleUnitModN(n)
        return Pair(encryptWithNonce(m, nonce), nonce)
    }

    // encryptWithNonce returns the encryption of m under the public key pk.
    // ct = (1+N)ᵐρᴺ (mod N²).
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

    override fun equals(other: Any?): Boolean {
        return (other is PaillierPublic) && n.compareTo(other.n) == 0
    }


    // validateCiphertexts checks if all ciphertexts are in the correct range and coprime to N²
    // ct ∈ [1, …, N²-1] AND GCD(ct,N²) = 1.
    fun validateCiphertexts(vararg cts: PaillierCipherText): Boolean {
        for (ct in cts) {
            if (!ct.c.gcd(nSquared).equals(BigInteger.ONE) ) return false
        }
        return true
    }
}

// ValidateN performs basic checks to make sure the modulus is valid:
// - log₂(n) = params.BitsPaillier.
// - n is odd.
fun validateN(n: BigInteger): Exception? {
    if (n.signum() <= 0) return IllegalArgumentException("modulus N is nil")
    if (n.bitLength() != BitsPaillier) {
        return IllegalArgumentException("Expected bit length: $BitsPaillier, found: ${n.bitLength()}")
    }
    if (!n.testBit(0)) return IllegalArgumentException("Modulus N is even")

    return null
}


/** Paillier's Secret Key **/
// Define the errors
val ErrPrimeBadLength = IllegalArgumentException("Prime factor is not the right length")
val ErrNotBlum = IllegalArgumentException("Prime factor is not equivalent to 3 (mod 4)")
val ErrNotSafePrime = IllegalArgumentException("Supposed prime factor is not a safe prime")

// SecretKey is the secret key corresponding to a Public Paillier Key.
data class PaillierSecret(
    val p: BigInteger,
    val q: BigInteger,
    val phi: BigInteger,
    val phiInv: BigInteger,
    val publicKey: PaillierPublic
) {
    // Decrypts c and returns the plaintext m ∈ ± (N-2)/2.
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

    // Extension function to handle result modulo ±(N-2)/2 range
    private fun BigInteger.toModSymmetric(n: BigInteger): BigInteger {
        val halfN = n.subtract(BigInteger.TWO).divide(BigInteger.TWO)
        return if (this > halfN) this.subtract(n) else this
    }

    // decryptWithRandomness returns the underlying plaintext, as well as the randomness used.
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

    // GeneratePedersen generates parameters for Pedersen commitment.
    fun generatePedersen(): Pair<PedersenParameters, BigInteger> {
        val n = publicKey.n
        val (s, t, lambda) = samplePedersen(phi, publicKey.n)
        val ped = PedersenParameters(n, s, t)
        return ped to lambda
    }
}

// Generates a new PublicKey and its associated SecretKey.
fun paillierKeyGen(): Pair<PaillierPublic, PaillierSecret> {
    val sk = newPaillierSecret()
    return sk.publicKey to sk
}

// Generates primes p and q suitable for the scheme, and returns the initialized SecretKey.
fun newPaillierSecret(): PaillierSecret {
    val (p, q) = generatePaillierBlumPrimes()
    return newPaillierSecretFromPrimes(p, q)
}

// Generates a new SecretKey from given primes p and q.
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

// validatePrime checks whether p is a suitable prime for Paillier.
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
