/**
 * @file skinny.h
 * @author Elias Hagelberg
 * @brief This file contains the declaration for the cipher functions of
 * SKINNY-128-384 block cipher.
 * Cipher specs in section 2.3 of SKINNY-AEAD specification:
 * https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/round-2/spec-doc-rnd2/SKINNY-spec-round2.pdf
 * @date 2021-12-05
 */

/**
 * @brief Performs the SubCells operation
 * 
 * @param IS Array containing the text to be ciphered 
 */
void subCells(unsigned char *IS);

/**
 * @brief Performs the AddConstants operation
 * 
 * @param IS Array containing the text to be ciphered 
 * @param round Indicator of round number. Used to pick right constant
 */
void addConstants(unsigned char *IS, int round);

/**
 * @brief Performs the AddRoundTweakey operation
 * 
 * @param IS Array containing the text to be ciphered 
 * @param TK1 Tweakey 1
 * @param TK2 Tweakey 2
 * @param TK3 Tweakey 3
 */
void addRoundTweakey(unsigned char *IS, unsigned char *TK1, unsigned char *TK2, unsigned char *TK3);

/**
 * @brief Performs the ShiftRows operation
 * 
 * @param IS  Array containing the text to be ciphered 
 */
void shiftRows(unsigned char *IS);

/**
 * @brief Performs the MixColumns operation
 * 
 * @param IS Array containing the text to be ciphered 
 */
void mixColumns(unsigned char *IS);

/**
 * SKINNY-128-384 block cipher encryption.
 * Under 48-byte tweakey at k, encrypt 16-byte plaintext at p and store the 16-byte output at c.
 */
void skinny(unsigned char *c, const unsigned char *p, const unsigned char *k);
