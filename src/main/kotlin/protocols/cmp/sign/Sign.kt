package perun_network.ecdsa_threshold.protocols.cmp.sign

import perun_network.ecdsa_threshold.internal.round.Helper
import perun_network.ecdsa_threshold.internal.round.Helper.Companion.newSession
import perun_network.ecdsa_threshold.internal.round.Info
import perun_network.ecdsa_threshold.internal.round.Number
import perun_network.ecdsa_threshold.internal.types.SigningMessage
import perun_network.ecdsa_threshold.math.curve.Point
import perun_network.ecdsa_threshold.math.polynomial.lagrangeCoefficient
import perun_network.ecdsa_threshold.party.ID
import perun_network.ecdsa_threshold.pool.Pool
import perun_network.ecdsa_threshold.protocol.StartFunc
import perun_network.ecdsa_threshold.protocols.cmp.config.Config
import perun_network.ecdsa_threshold.protocols.cmp.paillier.PublicKey
import perun_network.ecdsa_threshold.protocols.cmp.pedersen.Parameters

private const val PROTOCOL_SIGN_ID = "cmp/sign"
private const val PROTOCOL_SIGN_ROUNDS: UShort = 5u

fun startSign(config: Config?, signers: List<ID>, message: ByteArray, pool: Pool?): StartFunc {
    return StartFunc@{ sessionID: ByteArray ->
        if (config == null) {
            throw IllegalArgumentException("sign.Create: config is null")
        }

        if (message.isEmpty()) {
            throw IllegalArgumentException("sign.Create: message is nil")
        }

        val info = Info(
            selfID = config.id!!,
            partyIDs = signers,
            threshold = config.threshold!!,
            group = config.group,
            finalRoundNumber = Number(PROTOCOL_SIGN_ROUNDS),
            protocolID = PROTOCOL_SIGN_ID
        )

        val helper: Helper = newSession(info, sessionID, pool, config, SigningMessage(message))

        if (!config.canSign(helper.partyIDs())) {
            throw IllegalArgumentException("sign.Create: signers is not a valid signing subset")
        }

        val group = config.group
        val ecdsa = mutableMapOf<ID, Point>()
        val paillier = mutableMapOf<ID, PublicKey>()
        val pedersen = mutableMapOf<ID, Parameters>()
        var publicKey = group.newPoint()
        val lagrange = lagrangeCoefficient(group, signers)

        // Scale own secret
        val secretECDSA = group.newScalar().set(lagrange[config.id]!!).mul(config.ecdsa!!)
        val secretPaillier = config.paillier

        helper.partyIDs().forEach { j ->
            val public = config.public[j]!!
            ecdsa[j] = lagrange[j]!!.act(public.ecdsa)
            paillier[j] = public.paillier!!
            pedersen[j] = public.pedersen!!
            publicKey = publicKey.add(ecdsa[j]!!)
        }

        return@StartFunc Sign1(
            helper = helper,
            publicKey = publicKey,
            secretECDSA = secretECDSA,
            secretPaillier = secretPaillier,
            paillier = paillier,
            pedersen = pedersen,
            ecdsa = ecdsa,
            message = message
        )
    }
}