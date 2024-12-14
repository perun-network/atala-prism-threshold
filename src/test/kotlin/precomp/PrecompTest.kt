package precomp

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Test
import perun_network.ecdsa_threshold.precomp.generatePrecomputations
import kotlin.test.assertFails

class PrecompTest {
    @Test
    fun testGeneratePrecomp() {
        val n = 2
        val t = 1
        val (ids, secretPrecomps, publicPrecomps) = generatePrecomputations(n, t)

        // Verify the correct number of party IDs
        assertEquals(n, ids.size, "The number of party IDs should equal n")

        // Verify secret and public precomputations for all IDs
        assertEquals(ids.toSet(), secretPrecomps.keys.toSet(), "All IDs must have secret precomputations")
        assertEquals(ids.toSet(), publicPrecomps.keys.toSet(), "All IDs must have public precomputations")

        // Validate that the precomputations are not null and correctly initialized
        ids.forEach { id ->
            val secret = secretPrecomps[id]
            val public = publicPrecomps[id]
            assertNotNull(secret, "Secret precomputation for ID $id should not be null")
            assertNotNull(public, "Public precomputation for ID $id should not be null")
            assertEquals(secret!!.id, public!!.id, "Secret and public precomputation IDs must match")
            assertEquals(t, secret.threshold, "Threshold value in secret precomputation must match the input")
        }
    }

    @Test
    fun testGeneratePrecompFails() {
        val n = 3
        val t = 10

        // Simulate a case where `idRange` is smaller than `n`
        assertFails {
            generatePrecomputations(n, t) // Adjust the internal logic to simulate idRange < n
        }
    }
}