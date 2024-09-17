package perun_network.ecdsa_threshold.math

const val SecParam = 256
const val SecBytes = SecParam / 8
const val OTParam = 128
const val OTBytes = OTParam / 8
const val StatParam = 80

// ZKModIterations is the number of iterations that are performed to prove the validity of
// a Paillier-Blum modulus N.
// Theoretically, the number of iterations corresponds to the statistical security parameter,
// and would be 80.
// The way it is used in the refresh protocol ensures that the prover cannot guess in advance the secret ρ
// used to instantiate the hash function.
// Since sampling primes is expensive, we argue that the security can be reduced.
const val ZKModIterations = 12

const val L = 1 * SecParam     // = 256
const val LPrime = 5 * SecParam     // = 1280
const val Epsilon = 2 * SecParam     // = 512
const val LPlusEpsilon = L + Epsilon      // = 768
const val LPrimePlusEpsilon = LPrime + Epsilon // 1792

const val BitsIntModN = 8 * SecParam    // = 2048
const val BytesIntModN = BitsIntModN / 8 // = 256

const val BitsBlumPrime = 4 * SecParam      // = 1024
const val BitsPaillier = 2 * BitsBlumPrime // = 2048

const val BytesPaillier = BitsPaillier / 8  // = 256
const val BytesCiphertext = 2 * BytesPaillier // = 512