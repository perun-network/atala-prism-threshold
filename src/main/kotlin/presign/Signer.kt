package perun_network.ecdsa_threshold.presign

import perun_network.ecdsa_threshold.ecdsa.Scalar
import perun_network.ecdsa_threshold.keygen.PublicPrecomputation
import perun_network.ecdsa_threshold.keygen.SecretPrecomputation
import java.math.BigInteger

/**
 * Represents the secrets of the signer during the process of threshold signing.
 *
 * @property id The identifier of the signer.
 * @property private The signer's private precomputation, containing secret values.
 * @property publics A map of public precomputations, indexed by the signer's IDs.
 *
 * @property kShare The signer's share of the secret value `kᵢ` in the presigning protocol (Round 1).
 * @property gammaShare The signer's share of the secret value `gammaᵢ` in the presigning protocol (Round 1).
 * @property kNonce The signer's nonce value used in the presigning protocol (Round 1).
 * @property gNonce The group's nonce value used in the presigning protocol (Round 1).
 * @property chiShare The signer's share of the secret value `Xᵢ` in the presigning protocol (Round 3).
 */
data class ThresholdSigner(
    val id : Int, // i
    val private : SecretPrecomputation,
    val publics: Map<Int, PublicPrecomputation>,

    // PRESIGN ROUND 1
    var kShare : Scalar? = null, // k_i
    var gammaShare: Scalar? = null, // gamma_i
    var kNonce : BigInteger? = null,
    var gNonce : BigInteger? = null,

    // PRESIGN ROUND 3
    var chiShare: Scalar? = null, // X_i
)