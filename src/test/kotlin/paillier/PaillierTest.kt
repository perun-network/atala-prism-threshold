package paillier

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.assertThrows
import paillier.PaillierTestKeys.paillierPublic
import paillier.PaillierTestKeys.paillierSecret
import paillier.PaillierTestKeys.reinit
import perun_network.ecdsa_threshold.math.BitsPaillier
import perun_network.ecdsa_threshold.paillier.*
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertFailsWith

object PaillierTestKeys {
    var paillierPublic: PaillierPublic
    var paillierSecret: PaillierSecret

    init {
        val p = BigInteger("FD90167F42443623D284EA828FB13E374CBF73E16CC6755422B97640AB7FC77FDAF452B4F3A2E8472614EEE11CC8EAF48783CE2B4876A3BB72E9ACF248E86DAA5CE4D5A88E77352BCBA30A998CD8B0AD2414D43222E3BA56D82523E2073730F817695B34A4A26128D5E030A7307D3D04456DC512EBB8B53FDBD1DFC07662099B", 16)
        val q = BigInteger("DB531C32024A262A0DF9603E48C79E863F9539A82B8619480289EC38C3664CC63E3AC2C04888827559FFDBCB735A8D2F1D24BAF910643CE819452D95CAFFB686E6110057985E93605DE89E33B99C34140EF362117F975A5056BFF14A51C9CD16A4961BE1F02C081C7AD8B2A5450858023A157AFA3C3441E8E00941F8D33ED6B7", 16)
        paillierSecret = newPaillierSecretFromPrimes(p, q)
        paillierPublic = paillierSecret.publicKey
    }

    fun reinit() {
        val keys = paillierKeyGen()
        paillierPublic = keys.first
        paillierSecret = keys.second
    }
}

class PaillierTest {
    @Test
    fun testCiphertextValidate() {
        if (System.getProperty("runShortTests") == null) {
            reinit()
        }

        val C = BigInteger.ZERO
        var ct = PaillierCipherText(C)

        assertFailsWith<IllegalArgumentException> { paillierSecret.decrypt(ct) }

        val n = paillierPublic.n
        val nSquared = paillierPublic.nSquared

        ct = PaillierCipherText(n)
        assertFailsWith<IllegalArgumentException> { paillierSecret.decrypt(ct) }

        ct = PaillierCipherText(n + n)
        assertFailsWith<IllegalArgumentException> { paillierSecret.decrypt(ct) }

        ct =  PaillierCipherText(nSquared)
        assertFailsWith<IllegalArgumentException> { paillierSecret.decrypt(ct) }
    }

    @Test
    fun testEncDecRoundTrip() {
        if (System.getProperty("runShortTests") == null) {
           reinit()
        }

        val m = BigInteger.valueOf(42)
        val (ciphertext, _) = paillierPublic.encryptRandom(m)
        val decrypted = paillierSecret.decrypt(ciphertext)
        assertEquals(m, decrypted)
    }

    @Test
    fun testEncDecHomomorphic() {
        if (System.getProperty("runShortTests") == null) {
            reinit()
        }

        val a = BigInteger.valueOf(15)
        val b = BigInteger.valueOf(10)
        val (ca, _) = paillierPublic.encryptRandom(a)
        val (cb, _) = paillierPublic.encryptRandom(b)

        val expected = a + b
        val actual = paillierSecret.decrypt(ca.modMulNSquared(paillierPublic, cb))
        assertEquals(expected, actual)
    }

    @Test
    fun testEncDecScalingHomomorphic() {
        if (System.getProperty("runShortTests") == null) {
            reinit()
        }

        val x = BigInteger.valueOf(20)
        val s = BigInteger.valueOf(5)
        val (c, _)  = paillierPublic.encryptRandom(x)

        val expected = x * s
        val actual = paillierSecret.decrypt(c.modPowNSquared(paillierPublic, s))
        assertEquals(expected, actual)
    }

    @Test
    fun testDecWithRandomness() {
        if (System.getProperty("runShortTests") == null) {
            reinit()
        }

        val x = BigInteger.valueOf(7)
        val nonce = BigInteger.valueOf(13)
        val ciphertext = paillierPublic.encryptWithNonce(x, nonce)
        val (mActual, nonceActual) = paillierSecret.decryptRandom(ciphertext)

        assertEquals(x, mActual)
        assertEquals(nonce, nonceActual)
    }

    @Test
    fun `validateN should accept valid modulus`() {
        val validN = PRECOMPUTED_PRIMES[0].first.multiply(PRECOMPUTED_PRIMES[0].second) // p1 * q1
        assertNull(validateN(validN))
    }

    @Test
    fun `validateN should reject zero or negative modulus`() {
        assertEquals("modulus N is nil", validateN(BigInteger.ZERO)?.message)
        assertEquals("modulus N is nil", validateN(BigInteger.valueOf(-1))?.message)
    }

    @Test
    fun `validateN should reject modulus with incorrect bit length`() {
        val invalidN = BigInteger("1".repeat(BitsPaillier + 1), 2)
        assertEquals("Expected bit length: $BitsPaillier, found: ${invalidN.bitLength()}", validateN(invalidN)?.message)
    }

    @Test
    fun `validateN should reject even modulus`() {
        val evenN = BigInteger.valueOf(16)
        assertEquals("Modulus N is even", validateN(evenN)?.message)
    }

    @Test
    fun `validatePrime should accept valid prime`() {
        val validPrime = PRECOMPUTED_PRIMES[0].first
        assertTrue(validatePrime(validPrime))
    }

    @Test
    fun `validatePrime should reject prime of incorrect bit length`() {
        val shortPrime = BigInteger.valueOf(23) // Too short
        assertFailsWith<IllegalArgumentException> {
            validatePrime(shortPrime)
        }
    }

    @Test
    fun `validatePrime should reject non-Blum primes`() {
        val nonBlumPrime = BigInteger.valueOf(11) // 11 % 4 != 3
        assertFailsWith<IllegalArgumentException> {
            validatePrime(nonBlumPrime)
        }
    }

    @Test
    fun `validatePrime should reject non-safe primes`() {
        val nonSafePrime = BigInteger("19") // Not a safe prime
        assertFailsWith<IllegalArgumentException> {
            validatePrime(nonSafePrime)
        }
    }

    @Test
    fun `newPaillierSecretFromPrimes should generate correct secret`() {
        val p = PRECOMPUTED_PRIMES[0].first
        val q = PRECOMPUTED_PRIMES[0].second
        val secret = newPaillierSecretFromPrimes(p, q)

        assertEquals(p, secret.p)
        assertEquals(q, secret.q)
        assertEquals(p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)), secret.phi)
        assertTrue(secret.phiInv.multiply(secret.phi).mod(secret.publicKey.n) == BigInteger.ONE)
        assertEquals(secret.publicKey.n, p.multiply(q))
        assertEquals(secret.publicKey.nSquared, p.multiply(q).pow(2))
    }

    @Test
    fun `newPaillierSecretFromPrimes should fail on invalid primes`() {
        val invalidP = BigInteger("4") // Not prime
        val q = PRECOMPUTED_PRIMES[0].second

        assertThrows<IllegalArgumentException> {
            newPaillierSecretFromPrimes(invalidP, q)
        }
    }
}