//
// Created by alex on 11/11/17.
//
#include "./aes.h"
#include "../basics/GaloisFieldArithmetics.cpp"
#include <iostream>
#include <string>
#include <iomanip>
#include <cmath>

using namespace std;

/**
 * constructor, default Nb=4, Nk=4, Nr=10
 * @return
 */
AES::AES() {
    AES(4);
}

/**
 * constructor, set the Nk, with a default key
 * @param Nk
 * @return
 */
AES::AES(int nk) {
    u_int8_t key[4*nk] = {0x2b, 0x28, 0xab, 0x09,
                          0x7e, 0xae, 0xf7, 0xcf,
                          0x15, 0xd2, 0x15, 0x4f,
                          0x16, 0xa6, 0x88, 0x3c};
    AES(nk, key);
}

/**
 * constructor, set the Nk and the key
 * @param nk
 * @param key
 * @return
 */
AES::AES(int nk, u_int8_t * key) {
    //set Nb, Nk, Nr
    Nb = 4;
    switch (nk){
        case 4: {
            Nk = 4;
            Nr = 10;
            break;
        }
        case 6: {
            Nk = 6;
            Nr = 12;
            break;
        }
        case 8: {
            Nk = 8;
            Nr = 14;
            break;
        }
        default: {
            cout << "Wrong encrypt criteria parameter! Default parameters are adopted." << endl;
            Nk = 4;
            Nr = 10;
        }
    }
    //set the s_box, inv_s_box
    s_box = new u_int8_t[256]{
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    };
    inv_s_box = new u_int8_t[256]{
            0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
            0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
            0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
            0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
            0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
            0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
            0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
            0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
            0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
            0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
            0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
            0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
            0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
            0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
            0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
    };

    //set the keyMap

    KEYMAP = new u_int8_t[4*Nk*(Nr+1)];
    u_int8_t key_trans[4*Nk];
    trans_mat(key, key_trans, Nk);
    keyExpansion(key_trans, KEYMAP);
}

/**
 * constructor, set the Nk and the key, which is in string format
 * @param nk
 * @param key
 * @return
 */
AES::AES(int nk, string key) {
    u_int8_t * key_h = string_to_u_int8_t(key, 4*nk);
    Nb = 4;
    Nk = 4;
    Nr = 10;
    s_box = new u_int8_t[256]{
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    };
    inv_s_box = new u_int8_t[256]{
            0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
            0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
            0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
            0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
            0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
            0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
            0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
            0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
            0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
            0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
            0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
            0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
            0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
            0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
            0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
    };
    KEYMAP = new u_int8_t[4*Nk*(Nr+1)];
    u_int8_t key_trans[4*Nk];
    trans_mat(key_h, key_trans, Nk);
    keyExpansion(key_trans, KEYMAP);
}

/**
 * the implemented cipher function at the string level
 * @param in
 * @return
 */
string AES::cipher(const string &in) {
    string ret = "";
    string in_ext = "";
    int block_size = 4 * Nb;
    int block_num = (int)ceil(in.size() / (4 * Nb + 0.0));
    int i;
    for(i = 0; i < in.size(); i++){
        in_ext += in[i];
    }
    //personal modification to the text to be ciphered:
    //enlarge the size of the input string to fit the block size
    for(i = in.size(); i < block_num*(4*Nb); i++){
        in_ext += " ";
    }

    string tmp_str = "";
    string tmp_ciphered_str = "";
    u_int8_t *tmp_block = new u_int8_t[4*Nb];
    u_int8_t *tmp_ciphered_block = new u_int8_t[4*Nb];

    for(i = 0; i < block_num; i++){
        tmp_str = in_ext.substr(i*block_size, block_size);
        tmp_block = string_to_u_int8_t(tmp_str, block_size);
        //printBLOCK(tmp_block);
        aes_cipher(tmp_block, tmp_ciphered_block, KEYMAP);
        //printBLOCK(tmp_ciphered_block);
        tmp_ciphered_str = u_int8_t_to_string(tmp_ciphered_block, block_size);
        ret += tmp_ciphered_str;
    }
    return ret;
}

/**
 * the implemented decipher function at the string level
 * @param in
 * @return
 */
string AES::decipher(const string& in){
    string ret = "";
    string in_ext = "";
    int block_size = 4 * Nb;
    int block_num = (int)ceil(in.size() / (4 * Nb + 0.0));
    int i;
    for(i = 0; i < in.size(); i++){
        in_ext += in[i];
    }
    //personal modification to the text to be deciphered:
    //enlarge the size of the input string to fit the block size
    for(i = in.size(); i < block_num*(4*Nb); i++){
        in_ext += " ";
    }

    string tmp_str = "";
    string tmp_deciphered_str = "";
    u_int8_t *tmp_block = new u_int8_t[4*Nb];
    u_int8_t *tmp_deciphered_block = new u_int8_t[4*Nb];

    for(i = 0; i < block_num; i++){
        tmp_str = in_ext.substr(i*block_size, block_size);
        tmp_block = string_to_u_int8_t(tmp_str, block_size);
        //printBLOCK(tmp_block);
        inv_aes_cipher(tmp_block, tmp_deciphered_block, KEYMAP);
        //printBLOCK(tmp_deciphered_block);
        tmp_deciphered_str = u_int8_t_to_string(tmp_deciphered_block, block_size);
        ret += tmp_deciphered_str;
    }
    return ret;
}

u_int8_t* AES::getKeyMap() {
    return KEYMAP;
}


///////////////////////////////////////////////////////////////////////
//private
///////////////////////////////////////////////////////////////////////

/**
 * the process of ciphering
 * From fips-197
 * @param in        the input block
 * @param out       the output block
 * @param keyMap    the key map produced by process <key expansion>
 */
void AES::aes_cipher(u_int8_t *in, u_int8_t *out, u_int8_t *keyMap){
    int roundNum = 0;
    u_int8_t tmp[4*Nb];
    addRoundKey(in, keyMap, roundNum);
    for(roundNum = 1; roundNum <= Nr; roundNum++){
        subBytes(in);
        shiftRows(in);
        if(roundNum != Nr){
            mixColumns(in);
        }
        addRoundKey(in, keyMap, roundNum);
        if(roundNum == Nr){
            trans_mat(in, tmp);
            trans_mat(tmp, out);
        }
    }
}

/**
 * the process of inverse-ciphering
 * From fips-197
 * @param in        the input block
 * @param out       the output block
 * @param keyMap    the key map produced by process <inverse key expansion>
 */
void AES::inv_aes_cipher(u_int8_t *in, u_int8_t *out, u_int8_t *keyMap){
    int roundNum = Nr;
    u_int8_t tmp[4*Nb];
    addRoundKey(in, keyMap, roundNum);
    for(roundNum = Nr-1; roundNum >=0; roundNum--){
        inv_shiftRows(in);
        inv_subBytes(in);
        addRoundKey(in, keyMap, roundNum);
        if(roundNum != 0){
            inv_mixColumns(in);
        }
        if(roundNum == 0){
            trans_mat(in, tmp);
            trans_mat(tmp, out);
        }
    }

}

/**
 * the transposition of mat[4*Nb]
 * @param in
 * @param out
 */
void AES::trans_mat(u_int8_t *in, u_int8_t * out){
    int i,j;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            out[Nb*i+j] = in[i+4*j];
        }
    }
}

/**
 * the transposition of mat[4*size]
 * @param in
 * @param out
 */
void AES::trans_mat(u_int8_t *in, u_int8_t * out,int size){
    int i,j;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < size; j++) {
            out[size*i+j] = in[i+4*j];
        }
    }
}

/**
 * add the round key to the state
 * @param state         state block, note that items are placed horizontally
 * @param keyMap        the round key map, note that items are placed vertically
 * @param roundNum      the round number
 */
void AES::addRoundKey(u_int8_t * state, u_int8_t * keyMap, int roundNum){
    int i,j;
    for(i = 0;i < Nb; i++){ //iterate the columns of the state
        for(j = 0; j < 4; j++){ //iterate the rows of the state
            state[Nb*j+i] = g_add(state[Nb*j+i], keyMap[(roundNum*Nb+i)*4+j]);
        }
    }
}

/**
 * substitute the bytes from the state block, according to the s-box
 * @param state         state block, note that items are placed horitontally
 */
void AES::subBytes(u_int8_t *state){
    int i,j;
    for(i = 0;i < Nb; i++){ //iterate the columns of the state
        for(j = 0; j < 4; j++){ //iterate the rows of the state
            state[Nb*j+i] = substitute_u_int8_t(state[Nb*j+i]);
        }
    }
}

/**
 * the inverse process of subBytes()
 * @param state         state block, note that items are placed horitontally
 */
void AES::inv_subBytes(u_int8_t *state){
    int i,j;
    for(i = 0;i < Nb; i++){ //iterate the columns of the state
        for(j = 0; j < 4; j++){ //iterate the rows of the state
            state[Nb*j+i] = inv_substitute_u_int8_t(state[Nb*j+i]);
        }
    }
}

/**
 * shift the rows of a state block
 * @param state         state block, note that items are placed horitontally
 */
void AES::shiftRows(u_int8_t *state){
    int i,j;
    u_int8_t tmp;
    for(j = 0;j < 4; j++){ //iterate the rows of the state
        for(i = 0;i < j; i++){ //i counts the times of shift_step_one()
            shift_step_one(state, j);
        }
    }
}

void AES::shift_step_one(u_int8_t *state, int row){
    int i;
    u_int8_t tmp;
    tmp = state[Nb*row];  //tmp is the first item of the {row}-th row of the state
    for(i = 0; i < Nb-1; i++){ //iterate the columns of the state
        state[Nb*row+i] = state[Nb*row+i+1];
    }
    state[Nb*row+Nb-1] = tmp;
}

/**
 * shift the rows of a state block, in the inv_aes process
 * @param state         state block, note that items are placed horitontally
 */
void AES::inv_shiftRows(u_int8_t *state){
    int i,j;
    u_int8_t tmp;
    for(j = 0;j < 4; j++){ //iterate the rows of the state
        for(i = 0;i < j; i++){ //i counts the times of shift_step_one()
            inv_shift_step_one(state, j);
        }
    }
}

void AES::inv_shift_step_one(u_int8_t *state, int row){
    int i;
    u_int8_t tmp;
    tmp = state[Nb*row+Nb-1];  //tmp is the last item of the {row}-th row of the state
    for(i = Nb-1; i > 0; i--){ //iterate the columns of the state
        state[Nb*row+i] = state[Nb*row+i-1];
    }
    state[Nb*row+0] = tmp;
}

/**
 * from fips-197
 * @param state     state block, note that items are placed horitontally
 */
void AES::mixColumns(u_int8_t *state){
    int i,j;
    u_int8_t tmp_0, tmp_1, tmp_2, tmp_3;
    for(i = 0; i <= Nb-1; i++){ //iterate the columns of the state
        tmp_0 = state[Nb*0+i];
        tmp_1 = state[Nb*1+i];
        tmp_2 = state[Nb*2+i];
        tmp_3 = state[Nb*3+i];
        state[Nb*0+i] = g_add(g_add(g_add(g_mul(0x02, tmp_0),g_mul(0x03, tmp_1)), tmp_2), tmp_3);
        state[Nb*1+i] = g_add(g_add(g_add(g_mul(0x02, tmp_1),g_mul(0x03, tmp_2)), tmp_3), tmp_0);
        state[Nb*2+i] = g_add(g_add(g_add(g_mul(0x02, tmp_2),g_mul(0x03, tmp_3)), tmp_0), tmp_1);
        state[Nb*3+i] = g_add(g_add(g_add(g_mul(0x02, tmp_3),g_mul(0x03, tmp_0)), tmp_1), tmp_2);
    }
}

/**
 * from fips-197
 * @param state     state block, note that items are placed horitontally
 */
void AES::inv_mixColumns(u_int8_t *state){
    int i,j;
    u_int8_t tmp_0, tmp_1, tmp_2, tmp_3;
    for(i = 0; i <= Nb-1; i++){ //iterate the columns of the state
        tmp_0 = state[Nb*0+i];
        tmp_1 = state[Nb*1+i];
        tmp_2 = state[Nb*2+i];
        tmp_3 = state[Nb*3+i];
        state[Nb*0+i] = g_add(g_add(g_add(g_mul(0x0e, tmp_0),g_mul(0x0b, tmp_1)), g_mul(0x0d, tmp_2)), g_mul(0x09, tmp_3));
        state[Nb*1+i] = g_add(g_add(g_add(g_mul(0x0e, tmp_1),g_mul(0x0b, tmp_2)), g_mul(0x0d, tmp_3)), g_mul(0x09, tmp_0));
        state[Nb*2+i] = g_add(g_add(g_add(g_mul(0x0e, tmp_2),g_mul(0x0b, tmp_3)), g_mul(0x0d, tmp_0)), g_mul(0x09, tmp_1));
        state[Nb*3+i] = g_add(g_add(g_add(g_mul(0x0e, tmp_3),g_mul(0x0b, tmp_0)), g_mul(0x0d, tmp_1)), g_mul(0x09, tmp_2));
    }
}

/**
 * the 0th round, copy the key to the key map, and start the iteration
 * from fips-197
 * @param key       the original key, [4*Nk], note that items are placed horitontally
 * @param keyMap    the expanded key map, [4*(Nk*(Nr+1))], note that items are placed horitontally
 */
void AES::keyExpansion(u_int8_t * key, u_int8_t * keyMap){
    int i,j;
    for(i = 0;i < Nk; i++){ //iterate the columns of the key
        for(j = 0; j < 4; j++){ //iterate the rows of the key
            keyMap[i*4+j] = key[i*4+j];
        }
    }
    keyExpansion(keyMap, 1);
}

/**
 * the {round}th round, generate the {round}th key according to the given keyMap
 * @param keyMap
 * @param round
 */
void AES::keyExpansion(u_int8_t * keyMap,int round){
    if(round > Nr){
        return;
    }
    int i,j;
    u_int8_t x,y;
    u_int8_t w[4] = {};
    u_int8_t w_pre[4] = {};
    //rotate word
    w[0] = keyMap[(round*Nk-1)*4+1];
    w[1] = keyMap[(round*Nk-1)*4+2];
    w[2] = keyMap[(round*Nk-1)*4+3];
    w[3] = keyMap[(round*Nk-1)*4+0];
    w_pre[0] = keyMap[(round*Nk-4)*4+0];
    w_pre[1] = keyMap[(round*Nk-4)*4+1];
    w_pre[2] = keyMap[(round*Nk-4)*4+2];
    w_pre[3] = keyMap[(round*Nk-4)*4+3];
    //substitute bytes
    w[0] = substitute_u_int8_t(w[0]);
    w[1] = substitute_u_int8_t(w[1]);
    w[2] = substitute_u_int8_t(w[2]);
    w[3] = substitute_u_int8_t(w[3]);

    keyMap[(round*Nk)*4+0] = g_add(g_add(w[0], w_pre[0]), getRconFirstElement(round));
    keyMap[(round*Nk)*4+1] = g_add(w[1], w_pre[1]);
    keyMap[(round*Nk)*4+2] = g_add(w[2], w_pre[2]);
    keyMap[(round*Nk)*4+3] = g_add(w[3], w_pre[3]);
    for(i = 1; i <= 3; i++){
        for(j = 0; j < 4; j++){
            keyMap[(round*Nk+i)*4+j] = g_add(keyMap[(round*Nk+i-1)*4+j], keyMap[(round*Nk+i-4)*4+j]);
        }
    }
    /*
    translate_u_int8_t(w[0]);
    translate_u_int8_t(w[1]);
    translate_u_int8_t(w[2]);
    translate_u_int8_t(w[3]);
    //*/
    keyExpansion(keyMap, round+1);
}

/**
 * translate a single number from u_int8_t to int
 * @param num
 */
void AES::translate_u_int8_t(u_int8_t num){
    u_int8_t x,y;
    y = num & 0x0f;
    x = num & 0xf0;
    x = x >> 4;
    cout << "0x" << setbase(16) << (int)x << (int)y << " ";
}

/**
 * substitute a single number according to the s-box
 * @param num
 */
u_int8_t AES::substitute_u_int8_t(u_int8_t num){
    u_int8_t x,y;
    y = num & 0x0f;
    x = num & 0xf0;
    x = x >> 4;
    return s_box[16*x+y];
}

/**
 * substitute a single number according to the inv_s-box
 * @param num
 */
u_int8_t AES::inv_substitute_u_int8_t(u_int8_t num){
    u_int8_t x,y;
    y = num & 0x0f;
    x = num & 0xf0;
    x = x >> 4;
    return inv_s_box[16*x+y];
}

/**
 * from fips-197
 * get the first element of Rcon[i], which is defined as [{02}^(i-1), {00}, {00}, {00}] (i>=1)
 * @param i
 * @return
 */
u_int8_t AES::getRconFirstElement(int i){
    if(i==0){
        return 0x00;
    }
    if(i==1){
        return 0x01;
    }
    u_int8_t r = 0x02;
    i-=2;
    while(i>0){
        r = g_mul(r, 0x02);
        i--;
    }
    return r;
}

/**
 * parse string into u_int8_t array
 * @param str       input string
 * @param length    the max input length
 * @return
 */

u_int8_t * AES::string_to_u_int8_t(const string& str, int length){
    u_int8_t *result = new u_int8_t[length];
    int i;
    for(i=0;i<str.size();i++){
        result[i] = int(str[i]);
    }
    for(i=str.size();i<length-1;i++){
        result[i] = 0x00;
    }
    return result;
}

/**
 * parse hex string into ascii string
 * @param hex       hex string
 * @param length    the same of the hex string
 * @return
 */
string AES:: u_int8_t_to_string(u_int8_t *hex, int length){
    string ret="";
    for(int i=0;i<length;i++){
        ret += hex[i];
    }
    return ret;
}

/**
 * the method to print the items in the block
 * @param block
 */
void AES::printBLOCK(u_int8_t *block){
    int i,j;
    u_int8_t x,y;
    u_int8_t tmp[4*Nb] = {};
    trans_mat(block, tmp);
    for(i = 0; i < 4; i++){
        for(j = 0; j < Nb; j++){
            y = tmp[Nb*j+i] & 0x0f;
            x = tmp[Nb*j+i] & 0xf0;
            x = x >> 4;
            cout << "0x" << setbase(16) << (int)x << (int)y << " ";
        }
        cout << endl;
    }
    cout<<endl;
}