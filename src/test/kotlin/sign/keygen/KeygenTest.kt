package sign.keygen

import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.precomp.generateSessionId
import perun_network.ecdsa_threshold.sign.Broadcast
import perun_network.ecdsa_threshold.sign.aux.AuxRound2Broadcast
import perun_network.ecdsa_threshold.sign.keygen.Keygen
import perun_network.ecdsa_threshold.sign.keygen.KeygenRound1Broadcast
import perun_network.ecdsa_threshold.sign.keygen.KeygenRound2Broadcast
import perun_network.ecdsa_threshold.sign.keygen.KeygenRound3Broadcast
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails

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

    @Test
    fun testKeygenRound3Fails() {
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

        // Filter an entry
        assertFails {
            val round3AllBroadcasts = mutableMapOf<Int, Map<Int, KeygenRound3Broadcast>>()
            for (i in parties) {
                val incomingRound1Broadcasts = filterIncomingBroadcast(i, round1AllBroadcasts)
                val incomingRound2Broadcasts = filterIncomingBroadcast(i, round2AllBroadcasts)
                val modifiedRound2Broadcasts = incomingRound2Broadcasts.toMutableMap().filterKeys { j -> j == (i+1)%n + 1 }
                round3AllBroadcasts[i] =
                    keygenSigners[i]!!.keygenRound3(parties, incomingRound1Broadcasts, modifiedRound2Broadcasts)
            }
        }

        // Modify ssid.
        assertFails {
            val round3AllBroadcasts = mutableMapOf<Int, Map<Int, KeygenRound3Broadcast>>()
            for (i in parties) {
                val incomingRound1Broadcasts = filterIncomingBroadcast(i, round1AllBroadcasts)
                val incomingRound2Broadcasts = filterIncomingBroadcast(i, round2AllBroadcasts)
                val modifiedRound2Broadcasts = incomingRound2Broadcasts.toMutableMap()
                val modifiedId = (i+1)%n + 1
                modifiedRound2Broadcasts[modifiedId] = KeygenRound2Broadcast(
                    ssid = generateSessionId(),
                    from = incomingRound2Broadcasts[modifiedId]!!.from,
                    to = incomingRound2Broadcasts[modifiedId]!!.to,
                    rhoShare = incomingRound2Broadcasts[modifiedId]!!.rhoShare,
                    XShare = incomingRound2Broadcasts[modifiedId]!!.XShare,
                    AShare = incomingRound2Broadcasts[modifiedId]!!.AShare,
                    uShare = incomingRound2Broadcasts[modifiedId]!!.uShare
                )
                round3AllBroadcasts[i] =
                    keygenSigners[i]!!.keygenRound3(parties, incomingRound1Broadcasts, modifiedRound2Broadcasts)
            }
        }

        // Modify sender's id.
        assertFails {
            val round3AllBroadcasts = mutableMapOf<Int, Map<Int, KeygenRound3Broadcast>>()
            for (i in parties) {
                val incomingRound1Broadcasts = filterIncomingBroadcast(i, round1AllBroadcasts)
                val incomingRound2Broadcasts = filterIncomingBroadcast(i, round2AllBroadcasts)
                val modifiedRound2Broadcasts = incomingRound2Broadcasts.toMutableMap()
                val modifiedId = (i+1)%n + 1
                modifiedRound2Broadcasts[modifiedId] = KeygenRound2Broadcast(
                    ssid = incomingRound2Broadcasts[modifiedId]!!.ssid,
                    from = incomingRound2Broadcasts[i]!!.from,
                    to = incomingRound2Broadcasts[modifiedId]!!.to,
                    rhoShare = incomingRound2Broadcasts[modifiedId]!!.rhoShare,
                    XShare = incomingRound2Broadcasts[modifiedId]!!.XShare,
                    AShare = incomingRound2Broadcasts[modifiedId]!!.AShare,
                    uShare = incomingRound2Broadcasts[modifiedId]!!.uShare
                )
                round3AllBroadcasts[i] =
                    keygenSigners[i]!!.keygenRound3(parties, incomingRound1Broadcasts, modifiedRound2Broadcasts)
            }
        }

        // Modify receiver's id.
        assertFails {
            val round3AllBroadcasts = mutableMapOf<Int, Map<Int, KeygenRound3Broadcast>>()
            for (i in parties) {
                val incomingRound1Broadcasts = filterIncomingBroadcast(i, round1AllBroadcasts)
                val incomingRound2Broadcasts = filterIncomingBroadcast(i, round2AllBroadcasts)
                val modifiedRound2Broadcasts = incomingRound2Broadcasts.toMutableMap()
                val modifiedId = (i+1)%n + 1
                modifiedRound2Broadcasts[modifiedId] = KeygenRound2Broadcast(
                    ssid = incomingRound2Broadcasts[modifiedId]!!.ssid,
                    from = incomingRound2Broadcasts[modifiedId]!!.from,
                    to = incomingRound2Broadcasts[i]!!.to,
                    rhoShare = incomingRound2Broadcasts[modifiedId]!!.rhoShare,
                    XShare = incomingRound2Broadcasts[modifiedId]!!.XShare,
                    AShare = incomingRound2Broadcasts[modifiedId]!!.AShare,
                    uShare = incomingRound2Broadcasts[modifiedId]!!.uShare
                )
                round3AllBroadcasts[i] =
                    keygenSigners[i]!!.keygenRound3(parties, incomingRound1Broadcasts, modifiedRound2Broadcasts)
            }
        }

        // Modify rho_i.
        assertFails {
            val round3AllBroadcasts = mutableMapOf<Int, Map<Int, KeygenRound3Broadcast>>()
            for (i in parties) {
                val incomingRound1Broadcasts = filterIncomingBroadcast(i, round1AllBroadcasts)
                val incomingRound2Broadcasts = filterIncomingBroadcast(i, round2AllBroadcasts)
                val modifiedRound2Broadcasts = incomingRound2Broadcasts.toMutableMap()
                val modifiedId = (i+1)%n + 1
                modifiedRound2Broadcasts[modifiedId] = KeygenRound2Broadcast(
                    ssid = incomingRound2Broadcasts[modifiedId]!!.ssid,
                    from = incomingRound2Broadcasts[modifiedId]!!.from,
                    to = incomingRound2Broadcasts[modifiedId]!!.to,
                    rhoShare = incomingRound2Broadcasts[i]!!.rhoShare,
                    XShare = incomingRound2Broadcasts[modifiedId]!!.XShare,
                    AShare = incomingRound2Broadcasts[modifiedId]!!.AShare,
                    uShare = incomingRound2Broadcasts[modifiedId]!!.uShare
                )
                round3AllBroadcasts[i] =
                    keygenSigners[i]!!.keygenRound3(parties, incomingRound1Broadcasts, modifiedRound2Broadcasts)
            }
        }

        // Modify X_i.
        assertFails {
            val round3AllBroadcasts = mutableMapOf<Int, Map<Int, KeygenRound3Broadcast>>()
            for (i in parties) {
                val incomingRound1Broadcasts = filterIncomingBroadcast(i, round1AllBroadcasts)
                val incomingRound2Broadcasts = filterIncomingBroadcast(i, round2AllBroadcasts)
                val modifiedRound2Broadcasts = incomingRound2Broadcasts.toMutableMap()
                val modifiedId = (i+1)%n + 1
                modifiedRound2Broadcasts[modifiedId] = KeygenRound2Broadcast(
                    ssid = incomingRound2Broadcasts[modifiedId]!!.ssid,
                    from = incomingRound2Broadcasts[modifiedId]!!.from,
                    to = incomingRound2Broadcasts[modifiedId]!!.to,
                    rhoShare = incomingRound2Broadcasts[modifiedId]!!.rhoShare,
                    XShare = incomingRound2Broadcasts[i]!!.XShare,
                    AShare = incomingRound2Broadcasts[modifiedId]!!.AShare,
                    uShare = incomingRound2Broadcasts[modifiedId]!!.uShare
                )
                round3AllBroadcasts[i] =
                    keygenSigners[i]!!.keygenRound3(parties, incomingRound1Broadcasts, modifiedRound2Broadcasts)
            }
        }

        // Modify A_i.
        assertFails {
            val round3AllBroadcasts = mutableMapOf<Int, Map<Int, KeygenRound3Broadcast>>()
            for (i in parties) {
                val incomingRound1Broadcasts = filterIncomingBroadcast(i, round1AllBroadcasts)
                val incomingRound2Broadcasts = filterIncomingBroadcast(i, round2AllBroadcasts)
                val modifiedRound2Broadcasts = incomingRound2Broadcasts.toMutableMap()
                val modifiedId = (i+1)%n + 1
                modifiedRound2Broadcasts[modifiedId] = KeygenRound2Broadcast(
                    ssid = incomingRound2Broadcasts[modifiedId]!!.ssid,
                    from = incomingRound2Broadcasts[modifiedId]!!.from,
                    to = incomingRound2Broadcasts[modifiedId]!!.to,
                    rhoShare = incomingRound2Broadcasts[modifiedId]!!.rhoShare,
                    XShare = incomingRound2Broadcasts[modifiedId]!!.XShare,
                    AShare = incomingRound2Broadcasts[i]!!.AShare,
                    uShare = incomingRound2Broadcasts[modifiedId]!!.uShare
                )
                round3AllBroadcasts[i] =
                    keygenSigners[i]!!.keygenRound3(parties, incomingRound1Broadcasts, modifiedRound2Broadcasts)
            }
        }

        // Modify u_i.
        assertFails {
            val round3AllBroadcasts = mutableMapOf<Int, Map<Int, KeygenRound3Broadcast>>()
            for (i in parties) {
                val incomingRound1Broadcasts = filterIncomingBroadcast(i, round1AllBroadcasts)
                val incomingRound2Broadcasts = filterIncomingBroadcast(i, round2AllBroadcasts)
                val modifiedRound2Broadcasts = incomingRound2Broadcasts.toMutableMap()
                val modifiedId = (i+1)%n + 1
                modifiedRound2Broadcasts[modifiedId] = KeygenRound2Broadcast(
                    ssid = incomingRound2Broadcasts[modifiedId]!!.ssid,
                    from = incomingRound2Broadcasts[modifiedId]!!.from,
                    to = incomingRound2Broadcasts[modifiedId]!!.to,
                    rhoShare = incomingRound2Broadcasts[modifiedId]!!.rhoShare,
                    XShare = incomingRound2Broadcasts[modifiedId]!!.XShare,
                    AShare = incomingRound2Broadcasts[modifiedId]!!.AShare,
                    uShare = incomingRound2Broadcasts[i]!!.uShare
                )
                round3AllBroadcasts[i] =
                    keygenSigners[i]!!.keygenRound3(parties, incomingRound1Broadcasts, modifiedRound2Broadcasts)
            }
        }
    }

    @Test
    fun testKeygenOutputFails() {
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

        val publics = mutableMapOf<Int, Point>()
        assertFails {
            for (i in parties) {
                val incomingRound2Broadcasts = filterIncomingBroadcast(i, round2AllBroadcasts)
                val incomingRound3Broadcasts = filterIncomingBroadcast(i, round3AllBroadcasts)
                val modifiedRound2Broadcasts = incomingRound2Broadcasts.toMutableMap().filterKeys { j -> j == (i+1)%n + 1 }
                val (_, _, public) = keygenSigners[i]!!.keygenOutput(parties, modifiedRound2Broadcasts, incomingRound3Broadcasts)
                publics[i] = public
            }
        }

        // Modify ssid.
        assertFails {
            for (i in parties) {
                val incomingRound3Broadcasts = filterIncomingBroadcast(i, round3AllBroadcasts)
                val incomingRound2Broadcasts = filterIncomingBroadcast(i, round2AllBroadcasts)
                val modifiedRound2Broadcasts = incomingRound2Broadcasts.toMutableMap()
                val modifiedId = (i+1)%n + 1
                modifiedRound2Broadcasts[modifiedId] = KeygenRound2Broadcast(
                    ssid = generateSessionId(),
                    from = incomingRound2Broadcasts[modifiedId]!!.from,
                    to = incomingRound2Broadcasts[modifiedId]!!.to,
                    rhoShare = incomingRound2Broadcasts[modifiedId]!!.rhoShare,
                    XShare = incomingRound2Broadcasts[modifiedId]!!.XShare,
                    AShare = incomingRound2Broadcasts[modifiedId]!!.AShare,
                    uShare = incomingRound2Broadcasts[modifiedId]!!.uShare
                )
                val (_, _, public) = keygenSigners[i]!!.keygenOutput(parties, modifiedRound2Broadcasts, incomingRound3Broadcasts)
            }
        }

        // Modify sender's id.
        assertFails {
            for (i in parties) {
                val incomingRound3Broadcasts = filterIncomingBroadcast(i, round3AllBroadcasts)
                val incomingRound2Broadcasts = filterIncomingBroadcast(i, round2AllBroadcasts)
                val modifiedRound2Broadcasts = incomingRound2Broadcasts.toMutableMap()
                val modifiedId = (i+1)%n + 1
                modifiedRound2Broadcasts[modifiedId] = KeygenRound2Broadcast(
                    ssid = incomingRound2Broadcasts[modifiedId]!!.ssid,
                    from = incomingRound2Broadcasts[i]!!.from,
                    to = incomingRound2Broadcasts[modifiedId]!!.to,
                    rhoShare = incomingRound2Broadcasts[modifiedId]!!.rhoShare,
                    XShare = incomingRound2Broadcasts[modifiedId]!!.XShare,
                    AShare = incomingRound2Broadcasts[modifiedId]!!.AShare,
                    uShare = incomingRound2Broadcasts[modifiedId]!!.uShare
                )
                val (_, _, public) = keygenSigners[i]!!.keygenOutput(parties, modifiedRound2Broadcasts, incomingRound3Broadcasts)
            }
        }

        // Modify receiver's id.
        assertFails {
            for (i in parties) {
                val incomingRound3Broadcasts = filterIncomingBroadcast(i, round3AllBroadcasts)
                val incomingRound2Broadcasts = filterIncomingBroadcast(i, round2AllBroadcasts)
                val modifiedRound2Broadcasts = incomingRound2Broadcasts.toMutableMap()
                val modifiedId = (i+1)%n + 1
                modifiedRound2Broadcasts[modifiedId] = KeygenRound2Broadcast(
                    ssid = incomingRound2Broadcasts[modifiedId]!!.ssid,
                    from = incomingRound2Broadcasts[modifiedId]!!.from,
                    to = incomingRound2Broadcasts[i]!!.to,
                    rhoShare = incomingRound2Broadcasts[modifiedId]!!.rhoShare,
                    XShare = incomingRound2Broadcasts[modifiedId]!!.XShare,
                    AShare = incomingRound2Broadcasts[modifiedId]!!.AShare,
                    uShare = incomingRound2Broadcasts[modifiedId]!!.uShare
                )
                val (_, _, public) = keygenSigners[i]!!.keygenOutput(parties, modifiedRound2Broadcasts, incomingRound3Broadcasts)
            }
        }

        // Modify rho_i.
        assertFails {
            for (i in parties) {
                val incomingRound3Broadcasts = filterIncomingBroadcast(i, round3AllBroadcasts)
                val incomingRound2Broadcasts = filterIncomingBroadcast(i, round2AllBroadcasts)
                val modifiedRound2Broadcasts = incomingRound2Broadcasts.toMutableMap()
                val modifiedId = (i+1)%n + 1
                modifiedRound2Broadcasts[modifiedId] = KeygenRound2Broadcast(
                    ssid = incomingRound2Broadcasts[modifiedId]!!.ssid,
                    from = incomingRound2Broadcasts[modifiedId]!!.from,
                    to = incomingRound2Broadcasts[modifiedId]!!.to,
                    rhoShare = incomingRound2Broadcasts[i]!!.rhoShare,
                    XShare = incomingRound2Broadcasts[modifiedId]!!.XShare,
                    AShare = incomingRound2Broadcasts[modifiedId]!!.AShare,
                    uShare = incomingRound2Broadcasts[modifiedId]!!.uShare
                )
                val (_, _, public) = keygenSigners[i]!!.keygenOutput(parties, modifiedRound2Broadcasts, incomingRound3Broadcasts)
            }
        }

        // Modify X_i.
        assertFails {
            for (i in parties) {
                val incomingRound3Broadcasts = filterIncomingBroadcast(i, round3AllBroadcasts)
                val incomingRound2Broadcasts = filterIncomingBroadcast(i, round2AllBroadcasts)
                val modifiedRound2Broadcasts = incomingRound2Broadcasts.toMutableMap()
                val modifiedId = (i+1)%n + 1
                modifiedRound2Broadcasts[modifiedId] = KeygenRound2Broadcast(
                    ssid = incomingRound2Broadcasts[modifiedId]!!.ssid,
                    from = incomingRound2Broadcasts[modifiedId]!!.from,
                    to = incomingRound2Broadcasts[modifiedId]!!.to,
                    rhoShare = incomingRound2Broadcasts[modifiedId]!!.rhoShare,
                    XShare = incomingRound2Broadcasts[i]!!.XShare,
                    AShare = incomingRound2Broadcasts[modifiedId]!!.AShare,
                    uShare = incomingRound2Broadcasts[modifiedId]!!.uShare
                )
                val (_, _, public) = keygenSigners[i]!!.keygenOutput(parties, modifiedRound2Broadcasts, incomingRound3Broadcasts)
            }
        }

        // Modify A_i.
        assertFails {
            for (i in parties) {
                val incomingRound3Broadcasts = filterIncomingBroadcast(i, round3AllBroadcasts)
                val incomingRound2Broadcasts = filterIncomingBroadcast(i, round2AllBroadcasts)
                val modifiedRound2Broadcasts = incomingRound2Broadcasts.toMutableMap()
                val modifiedId = (i+1)%n + 1
                modifiedRound2Broadcasts[modifiedId] = KeygenRound2Broadcast(
                    ssid = incomingRound2Broadcasts[modifiedId]!!.ssid,
                    from = incomingRound2Broadcasts[modifiedId]!!.from,
                    to = incomingRound2Broadcasts[modifiedId]!!.to,
                    rhoShare = incomingRound2Broadcasts[modifiedId]!!.rhoShare,
                    XShare = incomingRound2Broadcasts[modifiedId]!!.XShare,
                    AShare = incomingRound2Broadcasts[i]!!.AShare,
                    uShare = incomingRound2Broadcasts[modifiedId]!!.uShare
                )
                val (_, _, public) = keygenSigners[i]!!.keygenOutput(parties, modifiedRound2Broadcasts, incomingRound3Broadcasts)
            }
        }

        // Modify u_i.
        assertFails {
            for (i in parties) {
                val incomingRound3Broadcasts = filterIncomingBroadcast(i, round3AllBroadcasts)
                val incomingRound2Broadcasts = filterIncomingBroadcast(i, round2AllBroadcasts)
                val modifiedRound2Broadcasts = incomingRound2Broadcasts.toMutableMap()
                val modifiedId = (i+1)%n + 1
                modifiedRound2Broadcasts[modifiedId] = KeygenRound2Broadcast(
                    ssid = incomingRound2Broadcasts[modifiedId]!!.ssid,
                    from = incomingRound2Broadcasts[modifiedId]!!.from,
                    to = incomingRound2Broadcasts[modifiedId]!!.to,
                    rhoShare = incomingRound2Broadcasts[modifiedId]!!.rhoShare,
                    XShare = incomingRound2Broadcasts[modifiedId]!!.XShare,
                    AShare = incomingRound2Broadcasts[modifiedId]!!.AShare,
                    uShare = incomingRound2Broadcasts[i]!!.uShare
                )
                val (_, _, public) = keygenSigners[i]!!.keygenOutput(parties, modifiedRound2Broadcasts, incomingRound3Broadcasts)
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