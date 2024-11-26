package sign.keygen

import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.precomp.generateSessionId
import perun_network.ecdsa_threshold.sign.Broadcast
import perun_network.ecdsa_threshold.sign.keygen.Keygen
import perun_network.ecdsa_threshold.sign.keygen.KeygenRound1Broadcast
import perun_network.ecdsa_threshold.sign.keygen.KeygenRound2Broadcast
import perun_network.ecdsa_threshold.sign.keygen.KeygenRound3Broadcast
import kotlin.test.Test
import kotlin.test.assertEquals

class KeygenTest {
    @Test
    fun testKeygen() {
        val n = 5 // Number of total parties.

        val ssid = generateSessionId()

        val keygenSigners = mutableMapOf<Int, Keygen>()
        for (i in 1..n) {
            keygenSigners[i] = Keygen(
                ssid = ssid,
                id = i
            )
        }
        val parties = keygenSigners.keys.toList()

        // KEYGEN ROUND 1
        val round1AllBroadcasts = mutableMapOf<Int, Map<Int, KeygenRound1Broadcast>>()
        for (i in parties) {
            round1AllBroadcasts[i] = keygenSigners[i]!!.keygenRound1(parties)
        }

        // KEYGEN ROUND 2
        val round2AllBroadcasts = mutableMapOf<Int, Map<Int, KeygenRound2Broadcast>>()
        for (i in parties) {
            round2AllBroadcasts[i] = keygenSigners[i]!!.keygenRound2(parties)
        }

        // KEYGEN ROUND 3
        val round3AllBroadcasts = mutableMapOf<Int, Map<Int, KeygenRound3Broadcast>>()
        for (i in parties) {
            val incomingRound1Broadcasts = filterIncomingBroadcast(i, round1AllBroadcasts)
            val incomingRound2Broadcasts = filterIncomingBroadcast(i, round2AllBroadcasts)
            round3AllBroadcasts[i] = keygenSigners[i]!!.keygenRound3(parties, incomingRound1Broadcasts, incomingRound2Broadcasts)
        }

        // KEYGEN OUTPUT
        val publics = mutableMapOf<Int, Point>()
        for (i in parties) {
            val incomingRound2Broadcasts = filterIncomingBroadcast(i, round2AllBroadcasts)
            val incomingRound3Broadcasts = filterIncomingBroadcast(i, round3AllBroadcasts)
            val (_, _, public) = keygenSigners[i]!!.keygenOutput(parties, incomingRound2Broadcasts, incomingRound3Broadcasts)
            publics[i] = public
        }

        // Check all public Points
        val publicPoint = publics[1]!!
        for (i in parties) {
            assertEquals(publicPoint, publics[i])
        }
    }

    private fun <A : Broadcast> filterIncomingBroadcast(id : Int, broadcasts : Map<Int, Map<Int, A>>) : Map<Int, A> {
        val incomingBroadcasts = mutableMapOf<Int, A>()
        for ((j, broadcast) in broadcasts) {
            if (j != id) {
                incomingBroadcasts[j] = broadcast[id]!!
            }
        }
        return incomingBroadcasts
    }
}