package paillier

import org.junit.jupiter.api.Assertions.assertEquals
import paillier.PaillierTestKeys.paillierPublic
import paillier.PaillierTestKeys.paillierSecret
import paillier.PaillierTestKeys.reinit
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

}