package perun_network.ecdsa_threshold.protocols.cmp

import perun_network.ecdsa_threshold.math.curve.Curve

// Config represents the stored state of a party who participated in a successful Keygen protocol.
// It contains secret key material and should be safely stored.
typealias Config = perun_network.ecdsa_threshold.protocols.cmp.config.Config

// EmptyConfig creates an empty Config with a fixed group, ready for unmarshalling.
//
// This needs to be used for unmarshalling, otherwise the points on the curve can't
// be decoded.
fun emptyConfig(group: Curve): Config {
    return Config(
        group = group,
        chainKey = null,
        ecdsa = null,
        elGamal = null,
        id = null,
        paillier = null,
        public = mutableMapOf(),
        rid = null,
        threshold = null,
    )
}