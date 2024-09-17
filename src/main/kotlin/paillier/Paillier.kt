package perun_network.ecdsa_threshold.paillier

import perun_network.ecdsa_threshold.math.BitsBlumPrime
import perun_network.ecdsa_threshold.math.BitsPaillier
import perun_network.ecdsa_threshold.pedersen.PedersenParameters
import perun_network.ecdsa_threshold.math.SafePrimeGenerator.generatePaillierKeyPair
import perun_network.ecdsa_threshold.math.pedersen
import perun_network.ecdsa_threshold.math.unitModN
import java.math.BigInteger
import java.security.SecureRandom

class PaillierPublic (
    // n = p⋅q
    val n: BigInteger,
    // nSquared = n²
    val nSquared: BigInteger,
    // nPlusOne = n + 1
    val nPlusOne: BigInteger
) {
    companion object {
        fun newPublicKey(n: BigInteger): PaillierPublic {
            return PaillierPublic(n, n.multiply(n), n.add(BigInteger.ONE))
        }
    }

    fun n(): BigInteger {
        return this.n
    }

    // enc returns the encryption of m under the public key pk.
    // The nonce used to encrypt is returned.
    //
    // The message m must be in the range [-(N-1)/2, …, (N-1)/2] and panics otherwise.
    //
    // ct = (1+N)ᵐρᴺ (mod N²).
    fun enc(m: BigInteger): Pair<PaillierCipherText, BigInteger> {
        val nonce = unitModN(n)
        return Pair(encWithNonce(m, nonce), nonce)
    }

    // encWithNonce returns the encryption of m under the public key pk.
    // The nonce is not returned.
    //
    // The message m must be in the range [-(N-1)/2, …, (N-1)/2] and panics otherwise
    //
    // ct = (1+N)ᵐρᴺ (mod N²).
    fun encWithNonce(m: BigInteger, nonce: BigInteger): PaillierCipherText {
        val mAbs = m.abs()
        val nHalf = n.shiftRight(1)

        if (mAbs > nHalf) {
            throw IllegalArgumentException("Encrypt: tried to encrypt message outside of range [-(N-1)/2, …, (N-1)/2]")
        }

        val c = nPlusOne.modPow(m, nSquared)
        val rhoN = nonce.modPow(n, nSquared)

        return PaillierCipherText(c.mod(n).multiply(rhoN.mod(n)).mod(n))
    }

    override fun equals(other: Any?): Boolean {
        return (other is PaillierPublic) && n.compareTo(other.n) == 0
    }


    // ValidateCiphertexts checks if all ciphertexts are in the correct range and coprime to N²
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
val ErrPrimeNull = NullPointerException("Prime is nil")

// SecretKey is the secret key corresponding to a Public Paillier Key.
data class PaillierSecret(
    val p: BigInteger,
    val q: BigInteger,
    val phi: BigInteger,
    val phiInv: BigInteger,
    val publicKey: PaillierPublic
) {
    // P returns the first of the two factors composing this key.
    fun getP() = p

    // Q returns the second of the two factors composing this key.
    fun getQ() = q

    // Phi returns ϕ = (P-1)(Q-1).
    fun getPhi() = phi

    // Decrypts c and returns the plaintext m ∈ ± (N-2)/2.
    @Throws(IllegalArgumentException::class)
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
        return result
    }

    // decryptWithRandomness returns the underlying plaintext, as well as the randomness used.
    @Throws(IllegalArgumentException::class)
    fun decryptWithRandomness(ct: PaillierCipherText): Pair<BigInteger, BigInteger> {
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
        val (s, t, lambda) = pedersen(phi, publicKey.n)
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
    val (p, q) = generatePaillierKeyPair(SecureRandom())
    return newPaillierSecretFromPrimes(p!!, q!!)
}

// Generates a new SecretKey from given primes P and Q.
fun newPaillierSecretFromPrimes(P: BigInteger, Q: BigInteger): PaillierSecret {
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

    return PaillierSecret(
        p = P,
        q = Q,
        phi = phi,
        phiInv = phiInv,
        publicKey = PaillierPublic(n, nSquared, nPlusOne)
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

    if (!pMinus1Div2.isProbablePrime(2)) {
        throw ErrNotSafePrime
    }

    return true
}
