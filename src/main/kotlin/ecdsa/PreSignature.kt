package perun_network.ecdsa_threshold.ecdsa

import perun_network.ecdsa_threshold.internal.types.RID
import perun_network.ecdsa_threshold.math.curve.Curve
import perun_network.ecdsa_threshold.math.curve.Point
import perun_network.ecdsa_threshold.math.curve.Scalar
import perun_network.ecdsa_threshold.math.curve.fromHash
import perun_network.ecdsa_threshold.party.ID
import perun_network.ecdsa_threshold.party.IDSlice
import perun_network.ecdsa_threshold.party.PointMap

typealias SignatureShare = Scalar

data class PreSignature (
    val id: RID? = null,
    val r: Point,
    val rBar : PointMap,
    val s: PointMap,
    val kShare: Scalar,
    val chiShare: Scalar
) {
    companion object {
        fun emptyPreSignature(group: Curve) = PreSignature(
            r = group.newPoint(),
            rBar = PointMap(group),
            s = PointMap(group),
            kShare = group.newScalar(),
            chiShare = group.newScalar(),
        )
    }

    fun group() : Curve {
        return r.curve()
    }

    // SignatureShare returns this party's share σᵢ = kᵢm+rχᵢ, where s = ∑ⱼσⱼ.
    fun signatureShare(hash: ByteArray): Scalar {
        val m = fromHash(group(), hash)
        val rScalar = r.xScalar()
        val mk = m.mul(kShare)
        val rx = rScalar!!.mul(chiShare)
        return mk.add(rx)
    }

    // Signature combines the given shares σⱼ and returns a pair (R,S), where S=∑ⱼσⱼ.
    fun signature(shares: Map<ID, Scalar>): Signature {
        var s = group().newScalar()
        shares.values.forEach { sigma -> s = s.add(sigma) }
        return Signature(r, s)
    }

    // VerifySignatureShares should be called if the signature returned by PreSignature.Signature is not valid.
    // It returns the list of parties whose shares are invalid.
    fun verifySignatureShares(shares: Map<ID, Scalar>, hash: ByteArray): List<ID> {
        val culprits = mutableListOf<ID>()
        val rScalar = r.xScalar()
        val m = fromHash(group(), hash)
        for ((j, share) in shares) {
            val rj = rBar.points[j]
            val sj = s.points[j]
            if (rj == null || sj == null) {
                culprits.add(j)
                continue
            }
            val lhs = share.act(r)
            val rhs = m.act(rj).add(rScalar!!.act(sj))
            if (!lhs.equals(rhs)) {
                culprits.add(j)
            }
        }
        return culprits
    }

    // Validate checks if the pre-signature is valid.
    fun validate(): Exception? {
        if (rBar.points.size != s.points.size) {
            return IllegalArgumentException("presignature: different number of R, S shares")
        }
        for ((id, rPoint) in rBar.points) {
            val sPoint = s.points[id]
            if (sPoint == null || sPoint.isIdentity()) {
                return IllegalArgumentException("presignature: S invalid")
            }
            if (rPoint.isIdentity()) {
                return IllegalArgumentException("presignature: RBar invalid")
            }
        }
        if (r.isIdentity()) {
            return IllegalArgumentException("presignature: R is identity")
        }

        id?.let { if (!it.validate()) {
            return IllegalArgumentException("presignature: ID invalid")
            }
        } ?: return NullPointerException("presignature: ID is null")
        if (chiShare.isZero() || kShare.isZero()) {
            return IllegalArgumentException("ChiShare or KShare is invalid")
        }
        return null
    }

    // SignerIDs returns a list of party IDs that participated in the pre-signature.
    fun signerIDs(): IDSlice {
        return IDSlice.newIDSlice(rBar.points.keys.toList())
    }
}