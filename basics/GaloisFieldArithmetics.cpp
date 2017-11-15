//
// Created by alex on 11/11/17.
//
/** Basic implementations of Galois Field Arithmetics
 *  https://en.wikipedia.org/wiki/Finite_field_arithmetic
 */
#include "./GaloisFieldArithmetics.h"

/**
 * addition of two numbers in GF(2^8) finite field
 */
u_int8_t g_add(u_int8_t a, u_int8_t b){
    return a ^ b;
}

/**
 * subtraction of two numbers in GF(2^8) finite field
 */
u_int8_t g_sub(u_int8_t a, u_int8_t b){
    return a ^ b;
}

/**
 * multiplication of two numbers in GF(2^8) finite field
 */
u_int8_t g_mul(u_int8_t a, u_int8_t b){
    uint8_t p = 0; /* the product of the multiplication */
    while (a && b) {
        if (b & 1) /* if b is odd, then add the corresponding a to p (final product = sum of all a's corresponding to odd b's) */
            p ^= a; /* since we're in GF(2^m), addition is an XOR */

        if (a & 0x80) /* GF modulo: if a >= 128, then it will overflow when shifted left, so reduce */
            a = (a << 1) ^ 0x11b; /* XOR with the primitive polynomial x^8 + x^4 + x^3 + x + 1 (0b1_0001_1011) – you can change it but it must be irreducible */
        else
            a <<= 1; /* equivalent to a*2 */
        b >>= 1; /* equivalent to b // 2 */
    }
    return p;
}
