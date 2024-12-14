package perun_network.ecdsa_threshold.math

import java.math.BigInteger

/**
 * Computes the Jacobi symbol (x/y), which can be +1, -1, or 0.
 * @param x The numerator.
 * @param y The denominator (must be an odd integer).
 * @return The Jacobi symbol of (x/y).
 */
fun jacobi(x: BigInteger, y: BigInteger): Int {
    require(y > BigInteger.ZERO && y.and(BigInteger.ONE) == BigInteger.ONE) {
        "The second argument (y) must be an odd integer greater than zero."
    }

    var a = x
    var b = y
    var j = 1

    // Adjust sign of b
    if (b < BigInteger.ZERO) {
        if (a < BigInteger.ZERO) {
            j = -1
        }
        b = b.negate()
    }

    while (true) {
        if (b == BigInteger.ONE) {
            return j
        }
        if (a == BigInteger.ZERO) {
            return 0
        }

        // a = a mod b
        a = a.mod(b)
        if (a == BigInteger.ZERO) {
            return 0
        }

        // Handle factors of 2 in 'a'
        val s = a.lowestSetBit // Number of trailing zero bits in 'a'
        if (s % 2 != 0) {
            val bMod8 = b.and(BigInteger.valueOf(7)) // b % 8
            if (bMod8 == BigInteger.valueOf(3) || bMod8 == BigInteger.valueOf(5)) {
                j = -j
            }
        }

        // Divide a by 2^s
        a = a.shiftRight(s)

        // Swap numerator and denominator
        if (b.and(BigInteger.valueOf(3)) == BigInteger.valueOf(3) &&
            a.and(BigInteger.valueOf(3)) == BigInteger.valueOf(3)
        ) {
            j = -j
        }

        // Swap a and b
        val temp = a
        a = b
        b = temp
    }
}