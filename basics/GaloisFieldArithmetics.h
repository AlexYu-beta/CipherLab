//
// Created by alex on 11/11/17.
//

#ifndef CYPHERLAB_GALOISFIELDARITHMETICS_H
#define CYPHERLAB_GALOISFIELDARITHMETICS_H

/**
 * addition of two numbers in GF(2^8) finite field
 */
extern u_int8_t g_add(u_int8_t, u_int8_t);

/**
 * subtraction of two numbers in GF(2^8) finite field
 */
extern u_int8_t g_sub(u_int8_t, u_int8_t);

/**
 * multiplication of two numbers in GF(2^8) finite field
 */
extern u_int8_t g_mul(u_int8_t, u_int8_t);

#endif //CYPHERLAB_GALOISFIELDARITHMETICS_H
