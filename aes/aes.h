//
// Created by alex on 11/11/17.
//

#ifndef CYPHERLAB_AES_H
#define CYPHERLAB_AES_H
#include <iostream>
#include <string>
using namespace std;

class AES{
public:
    /**
     * constructor, default Nb=4, Nk=4, Nr=10
     * @return
     */
    AES();

    /**
     * constructor, set the Nk
     * @return
     */
    AES(int);

    /**
     * constructor, set the Nk and the key
     * @return
     */
    AES(int, u_int8_t*);

    /**
     * constructor, set the Nk and the key, which is in string format
     * @return
     */
    AES(int, string);

    /**
     * the interface to cipher at the string level
     * @return
     */
    string cipher(const string&);

    /**
     * the interface to decipher at the string level
     * @return
     */
    string decipher(const string&);

    /**
     * for test, get the key map of the encryptor
     * @return
     */
    u_int8_t *getKeyMap();

private:
    void trans_mat(u_int8_t *, u_int8_t *);
    void trans_mat(u_int8_t *, u_int8_t *,int);
    void addRoundKey(u_int8_t *, u_int8_t *, int);
    void subBytes(u_int8_t *);
    void inv_subBytes(u_int8_t *);
    void shiftRows(u_int8_t *);
    void inv_shiftRows(u_int8_t *);
    void shift_step_one(u_int8_t *, int);
    void inv_shift_step_one(u_int8_t *, int);
    void mixColumns(u_int8_t *);
    void inv_mixColumns(u_int8_t *);
    void keyExpansion(u_int8_t *, u_int8_t *);
    void keyExpansion(u_int8_t *,int);
    void translate_u_int8_t(u_int8_t);
    u_int8_t substitute_u_int8_t(u_int8_t);
    u_int8_t inv_substitute_u_int8_t(u_int8_t);
    u_int8_t getRconFirstElement(int);
    u_int8_t *string_to_u_int8_t(const string&, int);
    string u_int8_t_to_string(u_int8_t *, int);
    void printBLOCK(u_int8_t *);

    /**
     * the process of ciphering
     * From fips-197
     * @param in        the input block
     * @param out       the output block
     * @param keyMap    the key map produced by process <key expansion>
     */
    void aes_cipher(u_int8_t *in, u_int8_t *out, u_int8_t *keyMap);

    /**
     * the process of inverse-ciphering
     * From fips-197
     * @param in        the input block
     * @param out       the output block
     * @param keyMap    the key map produced by process <inverse key expansion>
     */
    void inv_aes_cipher(u_int8_t *in, u_int8_t *out, u_int8_t *keyMap);

    /**
     * Nb specifies the number of 32-bit word in an input block, the output block and the State, which are 128bits
     * From fips-197
     */
    int Nb;

    /**
     * Nk specifies the number of 32-bit word in a cipher key, which is 128bits, 192bits, or 256bits
     * From fips-197
     */
    int Nk;

    /**
     * Nr specifies the number of rounds to be performed, depending on the key size Nk:
     * Nr = 10 when Nk = 4
     * Nr = 12 when Nk = 6
     * Nr = 14 when Nk = 8
     * From fips-197
     */
    int Nr;

    /**
     * s_box specify the substitution rule for the process subBytes()
     * from https://en.wikipedia.org/wiki/Rijndael_S-box
     */
    u_int8_t *s_box;

    /**
     * inv_s_box specify the substitution rule for the process inv_subBytes()
     * from https://en.wikipedia.org/wiki/Rijndael_S-box
     */
    u_int8_t *inv_s_box;

    /**
     * keyMap is used to generate round key, through the process keyExpansion()
     */
    u_int8_t *KEYMAP;
};

#endif //CYPHERLAB_AES_H
