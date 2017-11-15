#include <iostream>
#include <string>
#include "./aes/aes.cpp"

using namespace std;
void test();
void printBlock(u_int8_t *);
void trans_mat(u_int8_t *in, u_int8_t * out);

/**
 * the controller and test interface
 * @return
 */
int main() {
    u_int8_t key_4[4*4] = {0x2b, 0x28, 0xab, 0x09,
                           0x7e, 0xae, 0xf7, 0xcf,
                           0x15, 0xd2, 0x15, 0x4f,
                           0x16, 0xa6, 0x88, 0x3c};
    u_int8_t key_6[4*6] = {0x2b, 0x28, 0xab, 0x09, 0x01, 0x10,
                           0x7e, 0xae, 0xf7, 0xcf, 0x02, 0x11,
                           0x15, 0xd2, 0x15, 0x4f, 0x03, 0x12,
                           0x16, 0xa6, 0x88, 0x3c, 0x04, 0x13};
    u_int8_t key_8[4*8] = {0x2b, 0x28, 0xab, 0x09, 0x2b, 0x28, 0xab, 0x09,
                           0x7e, 0xae, 0xf7, 0xcf, 0x7e, 0xae, 0xf7, 0xcf,
                           0x15, 0xd2, 0x15, 0x4f, 0x15, 0xd2, 0x15, 0x4f,
                           0x16, 0xa6, 0x88, 0x3c, 0x16, 0xa6, 0x88, 0x3c};
    string key_1 = "emmmmemmmmemmmme";
    AES *aes_128 = new AES(4, key_4);
    AES *aes_192 = new AES(6, key_6);
    AES *aes_256 = new AES(8, key_8);
    AES *aes = new AES(4, key_1);
    string input = "乌鸦坐飞机";
    cout << "ciphering: " << input << endl;

    string output_cip_128 = aes_128->cipher(input);
    string output_cip_192 = aes_192->cipher(input);
    string output_cip_256 = aes_256->cipher(input);
    string output_cip = aes->cipher(input);

    cout << "the ciphered text of [ AES-128 ] is: "<< endl;
    cout << output_cip_128 << endl;
    cout << "the ciphered text of [ AES-192 ] is: "<< endl;
    cout << output_cip_192 << endl;
    cout << "the ciphered text of [ AES-256 ] is: "<< endl;
    cout << output_cip_256 << endl;
    cout << "the ciphered text of [ AES-128 ] is: "<< endl;
    cout << output_cip << endl;

    string output_dec_128 = aes_128->decipher(output_cip_128);
    string output_dec_192 = aes_192->decipher(output_cip_192);
    string output_dec_256 = aes_256->decipher(output_cip_256);
    string output_dec = aes->decipher(output_cip);

    cout << "the deciphered text of [ AES-128 ] is: " << endl;
    cout << output_dec_128 << endl;
    cout << "the deciphered text of [ AES-192 ] is: " << endl;
    cout << output_dec_192 << endl;
    cout << "the deciphered text of [ AES-256 ] is: " << endl;
    cout << output_dec_256 << endl;
    cout << "the deciphered text of [ AES-128 ] is: " << endl;
    cout << output_dec << endl;
}

/**
 * the testing interface
 */
void test() {
    //runTest();
}

void printBlock(u_int8_t *block){
    int Nb = 4;
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

void trans_mat(u_int8_t *in, u_int8_t * out){
    int Nb = 4;
    int i,j;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            out[Nb*i+j] = in[i+4*j];
        }
    }
}