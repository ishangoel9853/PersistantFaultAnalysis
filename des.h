#ifndef DES_H
#define DES_H

#include <cstdint>
using namespace std;

#define ui64 uint64_t
#define ui32 uint32_t
#define ui8  uint8_t

// ------------------------------------------------------------------------
//----KEY SCHEDULER UTILITIES-----
// Permuted Choice 1 Table [7*8]
static const char PC1[] =
{
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,

    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4
};
// Permuted Choice 2 Table [6*8]
static const char PC2[] =
{
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};
// Iteration Shift Array
static const char ITERATION_SHIFT[] =
{
    1,  1,  2,  2,  2,  2,  2,  2,  1,  2,  2,  2,  2,  2,  2,  1
//  1   2   3   4   5   6   7   8   9  10  11  12  13  14  15  16
};
// --------------------------------------------------------------------


// ------------------------------------------------------------------------
//--------DES ENCRYPTION UTILITIES------------
#define LB32_MASK 0x00000001
#define LB64_MASK 0x0000000000000001
#define L64_MASK  0x00000000ffffffff

// Initial Permutation Table [8*8]
static const char IP[] =
{
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};

// Inverse Initial Permutation Table [8*8]
static const char FP[] =
{
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25
};

// Expansion table for Expansion D-BOX in f [6*8]
static const char EXPANSION[] =
{
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
};

// The S-Box tables in f [8*16*4]
static const char SBOX[8][64] =
{
    {
        // S1
        14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
         0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
         4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
        15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13
    },
    {
        // S2
        15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
         3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
         0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
        13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9
    },
    {
        // S3
        10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
        13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
        13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
         1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12
    },
    {
        // S4
         7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
        13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
        10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
         3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14
    },
    {
        // S5
         2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
        14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
         4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
        11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3
    },
    {
        // S6
        12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
        10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
         9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
         4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13
    },
    {
        // S7
         4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
        13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
         1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
         6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12
    },
    {
        // S8
        13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
         1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
         7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
         2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
    }
};

// Post S-Box permutation in f [4*8]
static const char PBOX[] =
{
    16,  7, 20, 21,
    29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25
};
// ------------------------------------------------------------------------


//Defining standart(Fault-free) DES class
class DES
{
public:
    DES(ui64 key);                                  // DES Constructor
    ui64 des(ui64 inp, bool mode);                  //Driver function for DES Encryption (Mode: True-Decryption False-Encryption)
    ui64 encrypt(ui64 inp);                         // DES encryption function(encrypt inp with object key)
    ui64 decrypt(ui64 inp);                         // DES decryption function(encrypt inp with object key)

protected:
    void key_gen(ui64 key);                         //DES key generation algorithm
    ui64 i_perm(ui64 inp);                          //Initial Permutation Function
    ui64 f_perm(ui64 inp);                          //Final Permutation Function
    void feistel_round(ui32 &Left, ui32 &Right, ui32 F);         //Basic Fiestel Round
    ui32 des_func(ui32 Right, ui64 key);            //Function "f" 
    ui64 sub_key[16];                               //Round Keys generated from key_gen algo (48 bits each)              
};


//-----------------------------------------------------------------------
//#pragma GCC push_options
#pragma GCC optimize ("unroll-loops")               //Parallel execution of loops


//-----------------KEY GENERATION-----------------------------
DES::DES(ui64 key)
{
    key_gen(key);
}

void DES::key_gen(ui64 key)
{
    //Setting "permuted_choice_1" as the first 56 bits of the key "key"
    ui64 permuted_choice_1 = 0; 
    for (ui8 i = 0; i < 56; i++)
    {
        permuted_choice_1 <<= 1;
        permuted_choice_1 |= (key >> (64-PC1[i])) & LB64_MASK;
    }

    // Splittong "permutation_choice_1 into two halves"
    ui32 C = (ui32) ((permuted_choice_1 >> 28) & 0x000000000fffffff);
    ui32 D = (ui32)  (permuted_choice_1 & 0x000000000fffffff);

    // Calculation of the 16 round keys
    for (ui8 i = 0; i < 16; i++)
    {
        // key schedule, shifting Ci and Di
        for (ui8 j = 0; j < ITERATION_SHIFT[i]; j++)
        {
            C = (0x0fffffff & (C << 1)) | (0x00000001 & (C >> 27));
            D = (0x0fffffff & (D << 1)) | (0x00000001 & (D >> 27));
        }

        ui64 permuted_choice_2 = (((ui64) C) << 28) | (ui64) D;

        sub_key[i] = 0;                     // 48 bits (2*24)
        for (ui8 j = 0; j < 48; j++)
        {
            sub_key[i] <<= 1;
            sub_key[i] |= (permuted_choice_2 >> (56-PC2[j])) & LB64_MASK;
        }
    }
}

//----------------------------\KEY GENERATION-------------------------------

//--------------------------DES ENCRYPTION----------------------------------

void DES::feistel_round(ui32 &Left, ui32 &Right, ui32 F)
{
    ui32 foo = Right;
    Right = Left ^ F;
    Left = foo;
}

ui64 DES::i_perm(ui64 inp)
{
    // Initial permutation
    ui64 result = 0;
    for (ui8 i = 0; i < 64; i++)
    {
        result <<= 1;
        result |= (inp >> (64-IP[i])) & LB64_MASK;
    }
    return result;
}

ui64 DES::f_perm(ui64 inp)
{
    // Final permutation
    ui64 result = 0;
    for (ui8 i = 0; i < 64; i++)
    {
        result <<= 1;
        result |= (inp >> (64-FP[i])) & LB64_MASK;
    }
    return result;
}

ui32 DES::des_func(ui32 Right, ui64 key) // des_func(Right,k) function
{
    // applying expansion permutation to convert Right to 48-bits
    ui64 sbox_inp = 0;


    for (ui8 i = 0; i < 48; i++)
    {
        sbox_inp <<= 1;
        sbox_inp |= (ui64) ((Right >> (32-EXPANSION[i])) & LB32_MASK);
    }

    // XORing expanded Ri with Ki(round key)
    sbox_inp = sbox_inp ^ key;

    // Applying S-Boxes function and returning 32-bit data
    ui32 sbox_out = 0;
    for (ui8 i = 0; i < 8; i++)
    {
        // Finding Row no. from outer bits
        char row = (char) ((sbox_inp & (0x0000840000000000 >> 6*i)) >> (42-6*i));
        row = (row >> 4) | (row & 0x01);

        // Finding Column no. from the middle 4 bits of input
        char column = (char) ((sbox_inp & (0x0000780000000000 >> 6*i)) >> (43-6*i));

        sbox_out <<= 4;
        sbox_out |= (ui32) (SBOX[i][16*row + column] & 0x0f);
    }

    // DES function straight DBox
    ui32 f_result = 0;
    for (ui8 i = 0; i < 32; i++)
    {
        f_result <<= 1;
        f_result |= (sbox_out >> (32 - PBOX[i])) & LB32_MASK;
    }

    return f_result;
}

ui64 DES::encrypt(ui64 inp)
{
    return des(inp, false);                 //Calling des function with mode "False" for encrypting "inp"
}

ui64 DES::decrypt(ui64 inp)
{
    return des(inp, true);                  //Calling des function with mode "True" for decrypting "inp"
}

ui64 DES::des(ui64 inp, bool mode)    //Mode:: True-Decryption, False-Encryption
{
    // Applying initial permutation
    inp = i_perm(inp);
    // Splitting "inp" into two 32-bit parts
    ui32 Right = (ui32) (inp & L64_MASK);
    ui32 Left = (ui32) (inp >> 32) & L64_MASK;
    
    ui32 F;
    // 16 round Encryption
    for (ui8 i = 0; i < 16; i++)
    {
        if(mode) F = des_func(Right, sub_key[15-i]);
        else F = des_func(Right, sub_key[i]);
        feistel_round(Left, Right, F);
    }

    // Swapping Left & R
    inp = (((ui64) Right) << 32) | (ui64) Left;
    // Applying final permutation
    return f_perm(inp);
}


//--------------------------\DES ENCRYPTION----------------------------------

#endif 