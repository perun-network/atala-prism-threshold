package perun_network.ecdsa_threshold.presign

import perun_network.ecdsa_threshold.ecdsa.Point
import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.ecdsa.newPoint
import perun_network.ecdsa_threshold.ecdsa.secp256k1Order
import perun_network.ecdsa_threshold.paillier.PaillierCipherText
import perun_network.ecdsa_threshold.paillier.PaillierPublic
import perun_network.ecdsa_threshold.pedersen.PedersenParameters
import perun_network.ecdsa_threshold.zkproof.logstar.LogStarPublic
import java.math.BigInteger

data class PresignRound3Output (
    val ssid: ByteArray,
    val id : Int,
    val chiShare : BigInteger,
    val deltaShare : BigInteger,
    val bigDeltaShare : Point,
    val gamma : Point,
)

class PresignRounxd3Input(
    val ssid: ByteArray,
    val id: Int,
    val gammaShare : BigInteger,
    val kShare: Scalar,
    val secretECDSA: BigInteger,
    val otherPartys : List<Int>
) {
    fun producePresign3Output(
        bigGammaShares: MutableMap<Int, Point>,
        deltaShareAlphas: MutableMap<Int, BigInteger>, // DeltaShareAlpha[j] = αᵢⱼ
        deltaShareBetas: MutableMap<Int, BigInteger>,  // DeltaShareBeta[j] = βᵢⱼ
        chiShareAlphas: MutableMap<Int, BigInteger>,   // ChiShareAlpha[j] = α̂ᵢⱼ
        chiShareBetas: MutableMap<Int, BigInteger>,    // ChiShareBeta[j] = β̂^ᵢⱼ
    ) : PresignRound3Output {
        // Γ = ∑ⱼ Γⱼ
        var gamma = newPoint()
        for (bigGammaShare in bigGammaShares.values) {
            gamma = gamma.add(bigGammaShare)
        }

        // Δᵢ = [kᵢ]Γ
        val bigDeltaShare = kShare.act(gamma)

        // δᵢ = γᵢ kᵢ
        var deltaShare = gammaShare.multiply(kShare.value)

        // χᵢ = xᵢ kᵢ
        var chiShare = secretECDSA.multiply(kShare.value)

        for (i in bigGammaShares.keys) {
            if (i != this.id) {
                //δᵢ += αᵢⱼ + βᵢⱼ
                deltaShare = deltaShare.add(deltaShareAlphas[i])
                deltaShare = deltaShare.add(deltaShareBetas[i])

                // χᵢ += α̂ᵢⱼ +  ̂βᵢⱼ
                chiShare = chiShare.add(chiShareAlphas[i])
                chiShare = chiShare.add(chiShareBetas[i])
            }
        }
        deltaShare = deltaShare.mod(secp256k1Order())
        chiShare = chiShare.mod(secp256k1Order())

        return PresignRound3Output(
            ssid = ssid,
            id = id,
            chiShare = chiShare,
            deltaShare = deltaShare,
            bigDeltaShare = bigDeltaShare,
            gamma = gamma,
        )
    }


}
