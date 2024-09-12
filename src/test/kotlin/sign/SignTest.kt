package sign

import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
import org.kotlincrypto.hash.sha2.SHA256
import perun_network.ecdsa_threshold.ecdsa.PartialSignature
import perun_network.ecdsa_threshold.ecdsa.PrivateKey
import perun_network.ecdsa_threshold.ecdsa.PublicKey
import java.math.BigInteger
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertTrue

class SignTest {
    @Test
    fun testSignUsingPrivateKey() {
        val privateKeyHex = Hex.decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".lowercase())
        assertTrue(Secp256k1.secKeyVerify(privateKeyHex))
        val privateKey = PrivateKey.newPrivateKey(privateKeyHex)

        // Message to sign
        val message = "Hello, Bitcoin!".toByteArray()
        val hash = SHA256().digest(message)
        val signature = privateKey.sign(hash)

        assertTrue(signature.verify(hash, privateKey.publicKey()))
    }


    @Test
    fun testSignUsingPartialSignature() {
        val message = "Hello World"
        val presigs = generatePresignatureMock()
    }

    fun generatePresignatureMock(){
    }
}