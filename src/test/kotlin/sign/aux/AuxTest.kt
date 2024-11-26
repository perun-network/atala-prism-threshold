package sign.aux

import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.precomp.PublicPrecomputation
import perun_network.ecdsa_threshold.precomp.generateSessionId
import perun_network.ecdsa_threshold.precomp.getSamplePrecomputations
import perun_network.ecdsa_threshold.sign.Broadcast
import perun_network.ecdsa_threshold.sign.aux.Aux
import perun_network.ecdsa_threshold.sign.aux.AuxRound1Broadcast
import perun_network.ecdsa_threshold.sign.aux.AuxRound2Broadcast
import perun_network.ecdsa_threshold.sign.aux.AuxRound3Broadcast
import kotlin.test.Test
import kotlin.test.assertEquals

class AuxTest {
    @Test
    fun testAux() {
        val n = 5 // Number of total parties.
        val t = 3 // Threshold value.

        val ssid = generateSessionId()

        val auxSigners = mutableMapOf<Int, Aux>()
        for (i in 1..n) {
            auxSigners[i] = Aux(
                ssid = ssid,
                id = i,
                threshold = t,
                previousShare = null,
                previousPublic = null,
            )
        }
        val parties = auxSigners.keys.toList()

        // KEYGEN ROUND 1
        val round1AllBroadcasts = mutableMapOf<Int, Map<Int, AuxRound1Broadcast>>()
        for (i in parties) {
            round1AllBroadcasts[i] = auxSigners[i]!!.auxRound1(parties)
        }

        // KEYGEN ROUND 2
        val round2AllBroadcasts = mutableMapOf<Int, Map<Int, AuxRound2Broadcast>>()
        for (i in parties) {
            round2AllBroadcasts[i] = auxSigners[i]!!.auxRound2(parties)
        }

        // KEYGEN ROUND 3
        val round3AllBroadcasts = mutableMapOf<Int, Map<Int, AuxRound3Broadcast>>()
        for (i in parties) {
            val incomingRound1Broadcasts = filterIncomingBroadcast(i, round1AllBroadcasts)
            val incomingRound2Broadcasts = filterIncomingBroadcast(i, round2AllBroadcasts)
            round3AllBroadcasts[i] = auxSigners[i]!!.auxRound3(parties, incomingRound1Broadcasts, incomingRound2Broadcasts)
        }

        // KEYGEN OUTPUT
        val allPublics = mutableMapOf<Int, Map<Int, PublicPrecomputation>>()
        for (i in parties) {
            val incomingRound2Broadcasts = filterIncomingBroadcast(i, round2AllBroadcasts)
            val incomingRound3Broadcasts = filterIncomingBroadcast(i, round3AllBroadcasts)
            val (_, publics) = auxSigners[i]!!.auxOutput(parties, incomingRound2Broadcasts, incomingRound3Broadcasts)
            allPublics[i] = publics
        }

        // Check all public Points
        val publicPrecomp = allPublics[1]!!
        for (i in parties) {
            for (j in parties) {
                assertEquals(publicPrecomp[j], allPublics[i]!![j]!!, "Inconsistent public precomputation at index $j party $i")
            }
        }
    }

    @Test
    fun testAuxRefresh() {
        val n = 5 // Number of total parties.
        val t = 3 // Threshold value.

        val ssid = generateSessionId()

        val (_, secretPrecomps, publicPrecomps) = getSamplePrecomputations(n, t)
        val publics = mutableMapOf<Int, Map<Int, Point>>()
        for (i in 1..n) {
            val map = mutableMapOf<Int, Point>()
            for (j in 1..n) {
                map[j] = publicPrecomps[j]!!.publicEcdsa
            }
            publics[i] = map
        }

        val auxSigners = mutableMapOf<Int, Aux>()
        for (i in 1..n) {
            auxSigners[i] = Aux(
                ssid = ssid,
                id = i,
                threshold = t,
                previousShare = secretPrecomps[i]!!.ecdsaShare,
                previousPublic = publics[i]!!,
            )
        }
        val parties = auxSigners.keys.toList()

        // KEYGEN ROUND 1
        val round1AllBroadcasts = mutableMapOf<Int, Map<Int, AuxRound1Broadcast>>()
        for (i in parties) {
            round1AllBroadcasts[i] = auxSigners[i]!!.auxRound1(parties)
        }

        // KEYGEN ROUND 2
        val round2AllBroadcasts = mutableMapOf<Int, Map<Int, AuxRound2Broadcast>>()
        for (i in parties) {
            round2AllBroadcasts[i] = auxSigners[i]!!.auxRound2(parties)
        }

        // KEYGEN ROUND 3
        val round3AllBroadcasts = mutableMapOf<Int, Map<Int, AuxRound3Broadcast>>()
        for (i in parties) {
            val incomingRound1Broadcasts = filterIncomingBroadcast(i, round1AllBroadcasts)
            val incomingRound2Broadcasts = filterIncomingBroadcast(i, round2AllBroadcasts)
            round3AllBroadcasts[i] = auxSigners[i]!!.auxRound3(parties, incomingRound1Broadcasts, incomingRound2Broadcasts)
        }

        // KEYGEN OUTPUT
        val allPublics = mutableMapOf<Int, Map<Int, PublicPrecomputation>>()
        for (i in parties) {
            val incomingRound2Broadcasts = filterIncomingBroadcast(i, round2AllBroadcasts)
            val incomingRound3Broadcasts = filterIncomingBroadcast(i, round3AllBroadcasts)
            val (_, public) = auxSigners[i]!!.auxOutput(parties, incomingRound2Broadcasts, incomingRound3Broadcasts)
            allPublics[i] = public
        }

        // Check all public Points
        val publicPrecomp = allPublics[1]!!
        for (i in parties) {
            for (j in parties) {
                assertEquals(publicPrecomp[j], allPublics[i]!![j]!!, "Inconsistent public precomputation at index $j party $i")
            }
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