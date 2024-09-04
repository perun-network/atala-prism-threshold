package perun_network.ecdsa_threshold.protocols.cmp.presign

import perun_network.ecdsa_threshold.ecdsa.PreSignature
import perun_network.ecdsa_threshold.hash.BytesWithDomain
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
import perun_network.ecdsa_threshold.protocols.cmp.keygen.Start
import perun_network.ecdsa_threshold.protocols.cmp.paillier.PublicKey
import perun_network.ecdsa_threshold.protocols.cmp.pedersen.Parameters

private const val PROTOCOL_OFFLINE_ID = "cmp/presign-offline"
private const val PROTOCOL_ONLINE_ID = "cmp/presign-online"
private const val PROTOCOL_FULL_ID = "cmp/presign-full"
private const val PROTOCOL_OFFLINE_ROUNDS: UShort = 7u
private const val PROTOCOL_FULL_ROUNDS: UShort = 8u

fun StartPresign(
    config: Config?,
    signers: List<ID>,
    message: ByteArray,
    pool: Pool?
) : StartFunc {
    return StartFunc@ { sessionID: ByteArray ->
        if (config == null) {
            throw IllegalArgumentException("presign: config is null")
        }

        val info = Info(
            selfID = config.id!!,
            partyIDs = signers,
            threshold = config.threshold!!,
            group = config.group,
            finalRoundNumber = Number(if (message.isEmpty()) PROTOCOL_OFFLINE_ROUNDS else PROTOCOL_FULL_ROUNDS),
            protocolID = if (message.isEmpty()) PROTOCOL_OFFLINE_ID else PROTOCOL_FULL_ID,
            )

        val helper: Helper = newSession(info, sessionID, pool, config, SigningMessage(message))

        if (!config.canSign(helper.partyIDs())) {
            throw IllegalArgumentException("sign.Create: signers is not a valid signing subset")
        }

        val T = helper.n()
        val group = config.group
        val ecdsa = mutableMapOf<ID, Point>()
        val elGamal = mutableMapOf<ID, Point>()
        val paillier = mutableMapOf<ID, PublicKey>()
        val pedersen = mutableMapOf<ID, Parameters>()
        var publicKey = group.newPoint()
        val lagrange = lagrangeCoefficient(group, signers)

        // Scale own secret
        val secretECDSA = group.newScalar().set(lagrange[config.id]!!).mul(config.ecdsa!!)
        helper.partyIDs().forEach { j ->
            val public = config.public[j]!!
            ecdsa[j] = lagrange[j]!!.act(public.ecdsa)
            elGamal[j] = public.elGamal
            paillier[j] = public.paillier!!
            pedersen[j] = public.pedersen!!
            publicKey = publicKey.add(ecdsa[j]!!)
        }

        return@StartFunc Presign1(
            helper = helper,
            pool = pool,
            secretECDSA = secretECDSA,
            secretElGamal = config.elGamal,
            secretPaillier = config.paillier,
            publicKey = publicKey,
            ecdsa = ecdsa,
            elGamal = elGamal,
            paillier = paillier,
            pedersen = pedersen,
            message = message
        )
    }
}

fun StartPresignOnline(
    config: Config?,
    presignature: PreSignature?,
    message: ByteArray,
    pool: Pool?
): StartFunc {
    return StartFunc@ { sessionID: ByteArray ->
        if (config == null || presignature == null) {
            throw IllegalArgumentException("presign: config or presignature is null")
        }

        if (message.isEmpty()) {
            throw IllegalArgumentException("sign.Create: message is nil")
        }

        presignature.validate()

        val signers = presignature.signerIDs()

        if (!config.canSign(signers)) {
            throw IllegalArgumentException("sign.Create: signers is not a valid signing subset")
        }

        val info = Info(
            protocolID = PROTOCOL_ONLINE_ID,
            finalRoundNumber = Number(PROTOCOL_FULL_ROUNDS),
            selfID = config.id!!,
            partyIDs = signers,
            threshold = config.threshold!!,
            group = config.group,
        )

        val helper = newSession(
            info,
            sessionID,
            pool,
            config,
            BytesWithDomain("PreSignatureID", presignature.id!!.toByteArray()),
            SigningMessage(message)
        )

        return@StartFunc Sign1(
            helper = helper,
            publicKey = config.publicPoint(),
            message = message,
            preSignature = presignature
        )
    }
}