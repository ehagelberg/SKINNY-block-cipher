/**
 * @file skinny.c
 * @author Elias Hagelberg, 272628, (elias.hagelberg@tuni.fi)
 * @brief This file contains the definition for the cipher functions of
 * SKINNY-128-384 block cipher.
 * Cipher specs in section 2.3 of SKINNY-AEAD specification:
 * https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/round-2/spec-doc-rnd2/SKINNY-spec-round2.pdf
 * @date 2021-12-05
 */

#include <stdio.h>
#include <stdint.h>
#include "skinny.h"
#include <string.h>

/* SKINNY Sbox */
static const uint8_t S8 [256] = {
    0x65, 0x4c, 0x6a, 0x42 ,0x4b ,0x63 ,0x43 ,0x6b ,0x55 ,0x75 ,0x5a ,0x7a ,0x53 ,0x73 ,0x5b ,0x7b ,
    0x35, 0x8c, 0x3a, 0x81 ,0x89 ,0x33 ,0x80 ,0x3b ,0x95 ,0x25 ,0x98 ,0x2a ,0x90 ,0x23 ,0x99 ,0x2b ,
    0xe5, 0xcc, 0xe8, 0xc1 ,0xc9 ,0xe0 ,0xc0 ,0xe9 ,0xd5 ,0xf5 ,0xd8 ,0xf8 ,0xd0 ,0xf0 ,0xd9 ,0xf9 ,
    0xa5, 0x1c, 0xa8, 0x12 ,0x1b ,0xa0 ,0x13 ,0xa9 ,0x05 ,0xb5 ,0x0a ,0xb8 ,0x03 ,0xb0 ,0x0b ,0xb9 ,
    0x32, 0x88, 0x3c, 0x85 ,0x8d ,0x34 ,0x84 ,0x3d ,0x91 ,0x22 ,0x9c ,0x2c ,0x94 ,0x24 ,0x9d ,0x2d ,
    0x62, 0x4a, 0x6c, 0x45 ,0x4d ,0x64 ,0x44 ,0x6d ,0x52 ,0x72 ,0x5c ,0x7c ,0x54 ,0x74 ,0x5d ,0x7d ,
    0xa1, 0x1a, 0xac, 0x15 ,0x1d ,0xa4 ,0x14 ,0xad ,0x02 ,0xb1 ,0x0c ,0xbc ,0x04 ,0xb4 ,0x0d ,0xbd ,
    0xe1, 0xc8, 0xec, 0xc5 ,0xcd ,0xe4 ,0xc4 ,0xed ,0xd1 ,0xf1 ,0xdc ,0xfc ,0xd4 ,0xf4 ,0xdd ,0xfd ,
    0x36, 0x8e, 0x38, 0x82 ,0x8b ,0x30 ,0x83 ,0x39 ,0x96 ,0x26 ,0x9a ,0x28 ,0x93 ,0x20 ,0x9b ,0x29 ,
    0x66, 0x4e, 0x68, 0x41 ,0x49 ,0x60 ,0x40 ,0x69 ,0x56 ,0x76 ,0x58 ,0x78 ,0x50 ,0x70 ,0x59 ,0x79 ,
    0xa6, 0x1e, 0xaa, 0x11 ,0x19 ,0xa3 ,0x10 ,0xab ,0x06 ,0xb6 ,0x08 ,0xba ,0x00 ,0xb3 ,0x09 ,0xbb ,
    0xe6, 0xce, 0xea, 0xc2 ,0xcb ,0xe3 ,0xc3 ,0xeb ,0xd6 ,0xf6 ,0xda ,0xfa ,0xd3 ,0xf3 ,0xdb ,0xfb ,
    0x31, 0x8a, 0x3e, 0x86 ,0x8f ,0x37 ,0x87 ,0x3f ,0x92 ,0x21 ,0x9e ,0x2e ,0x97 ,0x27 ,0x9f ,0x2f ,
    0x61, 0x48, 0x6e, 0x46 ,0x4f ,0x67 ,0x47 ,0x6f ,0x51 ,0x71 ,0x5e ,0x7e ,0x57 ,0x77 ,0x5f ,0x7f ,
    0xa2, 0x18, 0xae, 0x16 ,0x1f ,0xa7 ,0x17 ,0xaf ,0x01 ,0xb2 ,0x0e ,0xbe ,0x07 ,0xb7 ,0x0f ,0xbf ,
    0xe2, 0xca, 0xee, 0xc6 ,0xcf ,0xe7 ,0xc7 ,0xef ,0xd2 ,0xf2 ,0xde ,0xfe ,0xd7 ,0xf7 ,0xdf ,0xff};

/*Constants for AddConstants operation*/
static const unsigned char constants[62] = {
    0x01, 0x03, 0x07, 0x0f, 0x1f ,0x3e ,0x3d ,0x3b ,0x37 ,0x2f ,0x1e ,0x3c ,0x39 ,0x33 ,0x27 ,0x0e ,0x1d ,
    0x3a, 0x35, 0x2b, 0x16 ,0x2c ,0x18 ,0x30 ,0x21 ,0x02 ,0x05 ,0x0b ,0x17 ,0x2e ,0x1c ,0x38 ,0x31 ,
    0x23, 0x06, 0x0d, 0x1b ,0x36 ,0x2d ,0x1a ,0x34 ,0x29 ,0x12 ,0x24 ,0x08 ,0x11 ,0x22 ,0x04 ,0x09 ,
    0x13, 0x26, 0x0c, 0x19 ,0x32 ,0x25 ,0x0a ,0x15 ,0x2a ,0x14 ,0x28 ,0x10 ,0x20};

/*Binary matrix used in MixColumns operation*/
static const uint8_t M[4][4]= {
    {1, 0, 1, 1},
    {1, 0, 0, 0},
    {0, 1, 1, 0},
    {1, 0, 1, 0}};

/*Permutation indeces for the key permutation in AddRoundTweakey*/
static const uint8_t key_perm [16]= {9, 15, 8, 13, 10, 14, 12, 11, 0, 1, 2, 3, 4, 5, 6, 7};


/*Performs the SubCells operation*/
void subCells(unsigned char *IS) {

    //Goes through the array and swaps the value based on the Sbox
    for(int i = 0; i < 16; ++i){
            IS[i] = S8[IS[i]];
    }
}

/*Performs the AddConstants operation*/
void addConstants(unsigned char *IS, int round){

    //Get the correct values for constants c0 and c1
    unsigned char rc = constants[round]; 
    unsigned char c0 = rc << 4;
    c0 = c0 >> 4;
    unsigned char c1 = rc >> 4;

    //XOR the constants to the desired bytes
    IS[0] = IS[0]^c0;
    IS[4] = IS[4]^c1; 
    IS[8] = IS[8]^0x02;
}

/*Performs the AddRoundTweakey operation*/
void addRoundTweakey(unsigned char *IS, unsigned char *TK1, unsigned char *TK2, unsigned char *TK3){

    //XOR the keys to text to be ciphered
    for(int j = 0; j < 8; j++){
            IS[j] = IS[j]^TK1[j]^TK2[j]^TK3[j];
    }

    //Helper for storing temporary values
    unsigned char temp_key[16];
    memcpy(temp_key, TK1, sizeof(temp_key));

    //permutate TK1
    for(int i = 0; i < 16; ++i){
        TK1[i] = temp_key[key_perm[i]];
    }

    //permutate TK2
    memcpy(temp_key, TK2, sizeof(temp_key));
    for(int i = 0; i < 16; ++i){
        TK2[i] = temp_key[key_perm[i]];
    }

    //LFSR for TK2
    for(int i = 0; i < 8; ++i){
        unsigned char x7 = TK2[i] >> 7;
        unsigned char x5 = TK2[i] >> 5;
        x5 &= 0x01;
        x7 &= 0x01;
        unsigned char tempx = TK2[i] << 1;
        tempx |= (x5^x7); 
        TK2[i] = tempx;
    }

    //permutate TK3
    memcpy(temp_key, TK3, sizeof(temp_key));
    for(int i = 0; i < 16; ++i){
        TK3[i] = temp_key[key_perm[i]];
    }

    //LFSR for TK3
    for(int i = 0; i < 8; ++i){
        unsigned char x0 = TK3[i];
        unsigned char x6 = TK3[i] >> 6;
        x0 &= 0x01;
        x6 &= 0x01;
        unsigned char tempx = TK3[i] >> 1;
        tempx |= ((x0^x6) << 7); 
        TK3[i] = tempx;
    }
}

/*Performs the ShiftRows operation*/
void shiftRows(unsigned char *IS){

    //Just swaps positions of the cells
    unsigned char temp2[16] = {IS[0], IS[1], IS[2], IS[3], IS[7], IS[4], IS[5], IS[6],
                IS[10], IS[11], IS[8], IS[9], IS[13], IS[14], IS[15], IS[12]};
    memcpy(IS, temp2, 16);
}

/*Performs the MixColumns operation*/
void mixColumns(unsigned char *IS){

    //Transform IS to matrix for easier matrix multiplication
    unsigned char IS_as_matrix[4][4] = {
        {IS[0], IS[1], IS[2], IS[3]},
        {IS[4], IS[5], IS[6], IS[7]},
        {IS[8], IS[9], IS[10], IS[11]}, 
        {IS[12], IS[13], IS[14], IS[15]}};    

    //Matrix for storing the matrix multiplication answer
    unsigned char ans[4][4] = {0x00};

    //Loop structure for matrix multiplication
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            for(int l = 0; l < 4; l++){
                if(M[j][l] == 1){
                    ans[j][i] ^= IS_as_matrix[l][i];
                }                
            }     
        }
    }
    memcpy(IS, ans, 16);
}


/**
 * SKINNY-128-384 block cipher encryption.
 * Under 48-byte tweakey at k, encrypt 16-byte plaintext at p and store the 16-byte output at c.
 */
void skinny(unsigned char *c, const unsigned char *p, const unsigned char *k) {

    /*Initialize the IS array containing the plaintext and the 3 tweakeys*/
    int round = 0;
    unsigned char IS[16];
    memcpy(IS, p, sizeof(IS));

    unsigned char TK1[16]; 
    memcpy(TK1, k, sizeof(TK1));
    unsigned char TK2[16];
    memcpy(TK2, k+16, sizeof(TK2));
    unsigned char TK3[16];
    memcpy(TK3, k+32, sizeof(TK3));

    //Loop the cipher for 56 rounds
    while(round < 56){

        //Subcells
        subCells(IS);
        
        //AddConstants
        addConstants(IS, round);

        //AddRoundKey
        addRoundTweakey(IS, TK1, TK2, TK3);
        
        //shift rows
        shiftRows(IS);

        //MixColumns
        mixColumns(IS);

        round++;
    }

    //Copy the final ciphertext to c
    memcpy(c, IS, 16);
}
