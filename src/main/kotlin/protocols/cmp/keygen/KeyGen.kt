package perun_network.ecdsa_threshold.protocols.cmp.keygen

import perun_network.ecdsa_threshold.internal.round.*
import perun_network.ecdsa_threshold.math.curve.Curve
import perun_network.ecdsa_threshold.math.curve.Point
import perun_network.ecdsa_threshold.math.curve.Scalar
import perun_network.ecdsa_threshold.math.polynomial.Polynomial
import perun_network.ecdsa_threshold.math.polynomial.Polynomial.Companion.newPolynomial
import perun_network.ecdsa_threshold.math.sample.SecureRandomInputStream
import perun_network.ecdsa_threshold.math.sample.scalar
import perun_network.ecdsa_threshold.party.ID
import perun_network.ecdsa_threshold.pool.Pool
import perun_network.ecdsa_threshold.protocol.StartFunc
import perun_network.ecdsa_threshold.protocols.cmp.config.Config
import java.security.SecureRandom

val Rounds=  Number(5.toUShort())

fun Start(info: Info, pool: Pool?, config: Config?): StartFunc {
    return StartFunc@{ sessionID: ByteArray ->
        var helper: Helper = if (config == null) {
            Helper.newSession(info, sessionID, pool)
        } else {
            Helper.newSession(info, sessionID, pool, config)
        }

        val group: Curve = helper.group()

        if (config != null) {
            val PublicSharesECDSA: MutableMap<ID, Point> = mutableMapOf()
            for ((id, public) in config.public) {
                PublicSharesECDSA[id] = public.ecdsa
            }
            return@StartFunc Round1(
                helper = helper,
                previousSecretECDSA = config.ecdsa,
                previousPublicSharesECDSA = PublicSharesECDSA,
                previousChainKey = config.chainKey,
                vssSecret = newPolynomial(group, helper.threshold(), group.newScalar())
            )
        }

        // sample fᵢ(X) deg(fᵢ) = t, fᵢ(0) = secretᵢ
        val VSSConstant = scalar(SecureRandomInputStream(SecureRandom()), group)
        val VSSSecret = newPolynomial(group, helper.threshold(), VSSConstant)
        return@StartFunc Round1(
            helper = helper,
            vssSecret = VSSSecret
        )
    }
}