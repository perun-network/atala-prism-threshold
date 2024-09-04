package perun_network.ecdsa_threshold.internal.params

const val SEC_PARAM: Int = 256
const val SEC_BYTES: Int = SEC_PARAM / 8
const val OT_PARAM: Int = 128
const val OT_BYTES: Int = OT_PARAM / 8
const val STAT_PARAM: Int = 80

const val ZK_MOD_ITERATIONS: Int = 12

const val L: Int = 1 * SEC_PARAM  // 256
const val L_PRIME: Int = 5 * SEC_PARAM  // 1280
const val EPSILON: Int = 2 * SEC_PARAM  // 512
const val L_PLUS_EPSILON: Int = L + EPSILON  // 768
const val L_PRIME_PLUS_EPSILON: Int = L_PRIME + EPSILON  // 1792

const val BITS_INT_MOD_N: Int = 8 * SEC_PARAM  // 2048
const val BYTES_INT_MOD_N: Int = BITS_INT_MOD_N / 8  // 256

const val BITS_BLUM_PRIME: Int = 4 * SEC_PARAM  // 1024
const val BITS_PAILLIER: Int = 2 * BITS_BLUM_PRIME  // 2048

const val BYTES_PAILLIER: Int = BITS_PAILLIER / 8  // 256
const val BYTES_CIPHERTEXT: Int = 2 * BYTES_PAILLIER  // 512