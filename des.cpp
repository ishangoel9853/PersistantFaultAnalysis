#include "des.h"
#include <bits/stdc++.h>
// #include "des_key.h"
// #include "des_data.h"
// #include "des_lookup.h"

//#pragma GCC pop_options

#define N 10

ui64 v = 0x0000000000000000; // 48 bit representation of faulty indices in 8 S-Boxes.
ui8 V_MASK = 0x80;
char SBOX_Faulty[8][64] =
    {
        {// S1
         14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
         0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
         4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
         15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
        {// S2
         15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
         3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
         0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
         13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},
        {// S3
         10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
         13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
         13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
         1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},
        {// S4
         7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
         13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
         10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
         3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},
        {// S5
         2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
         14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
         4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
         11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},
        {// S6
         12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
         10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
         9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
         4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},
        {// S7
         4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
         13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
         1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
         6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},
        {// S8
         13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
         1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
         7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
         2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}};

class DES_Faulty : public DES
{
public:
    DES_Faulty(ui64 key);
    ui64 encrypt_Faulty(ui64 block);
    ui64 des_Faulty(ui64 block, bool mode);

protected:
    ui32 f_Faulty(ui32 R, ui64 k);
};

DES_Faulty::DES_Faulty(ui64 key) : DES(key)
{
}

ui64 DES_Faulty::encrypt_Faulty(ui64 block)
{
    return des_Faulty(block, false);
}

ui64 DES_Faulty::des_Faulty(ui64 block, bool mode)
{
    // Applying initial permutation
    block = ip(block);

    // Splitting "block" into two 32-bit parts
    ui32 L = (ui32)(block >> 32) & L64_MASK;
    ui32 R = (ui32)(block & L64_MASK);

    ui32 F;
    // 16 round Encryption
    for (ui8 i = 0; i < 16; i++)
    {
        if (i != 15)
            F = mode ? f(R, sub_key[15 - i]) : f(R, sub_key[i]);
        else
            F = mode ? f_Faulty(R, sub_key[15 - i]) : f_Faulty(R, sub_key[i]);

        feistel(L, R, F);
    }

    // Swapping L & R
    block = (((ui64)R) << 32) | (ui64)L;
    // Applying final permutation
    return fp(block);
}

ui32 DES_Faulty::f_Faulty(ui32 R, ui64 k) // f(R,k) function
{
    // applying expansion permutation to convert R to 48-bits
    ui64 s_input = 0;
    for (ui8 i = 0; i < 48; i++)
    {
        s_input <<= 1;
        s_input |= (ui64)((R >> (32 - EXPANSION[i])) & LB32_MASK);
    }

    // XORing expanded Ri with Ki(round key)
    s_input = s_input ^ k;

    // Applying S-Boxes function and returning 32-bit data
    ui32 s_output = 0;
    for (ui8 i = 0; i < 8; i++)
    {
        // Outer bits
        char row = (char)((s_input & (0x0000840000000000 >> 6 * i)) >> (42 - 6 * i));
        row = (row >> 4) | (row & 0x01);

        // Middle 4 bits of input
        char column = (char)((s_input & (0x0000780000000000 >> 6 * i)) >> (43 - 6 * i));

        s_output <<= 4;
        s_output |= (ui32)(SBOX_Faulty[i][16 * row + column] & 0x0f); //Using Fault injected S-Boxes
    }

    // Round permutation
    ui32 f_result = 0;
    for (ui8 i = 0; i < 32; i++)
    {
        f_result <<= 1;
        f_result |= (s_output >> (32 - PBOX[i])) & LB32_MASK;
    }

    return f_result;
}

void attack(ui64 inputs[N], ui8 mask, ui64 analysis[8][N])
{
    ui64 key = 0x0000000000000011;

    DES des(key);
    DES_Faulty des_f(key);

    ui64 recovered_key = 0x0000000000000000;

    ui8 key_pos = 0x00; // Recovered key positions 6 bits at a time
    ui8 L8_MASK = 0x01;

    // Persistent Fault Analysis
    for (int i = 0; i < N; i++)
    {
        ui64 result = des.encrypt(inputs[i]);
        ui64 result_faulty = des_f.encrypt(inputs[i]);

        if (result_faulty == result)
        {
            continue;
        }

        ui64 d_r = result ^ result_faulty;

        // Reverse final permutation for d_r
        ui64 before_fp = 0;
        for (ui8 i = 0; i < 64; i++)
        {
            before_fp <<= 1;
            before_fp |= (d_r >> (64 - IP[i])) & LB64_MASK;
        }

        ui32 a = before_fp >> 32;
        // Applying expansion permutation to convert a to 48-bits
        ui64 a1 = 0;
        for (ui8 i = 0; i < 48; i++)
        {
            a1 <<= 1;
            a1 |= (ui64)((a >> (32 - EXPANSION[i])) & LB32_MASK);
        }

        ui32 d_b = before_fp & L64_MASK;
        ui64 KEY_MASK = 0x000000000000003f;
        ui32 B_MASK = 0x0000000f;
        for (int j = 0; j < 8; j += 1)
        {
            if (!(key_pos ^ mask))
                break;
            if ((d_b & (B_MASK << (j * 4))) && !(key_pos & (L8_MASK << j)) && (mask & (1 << j)))
            {
                analysis[j][i] = 1;
                recovered_key |= (KEY_MASK << j) & (a1 ^ v);
                key_pos |= (L8_MASK << j);
                continue;
            }
            analysis[j][i]--;
        }
    }

    if (key_pos ^ mask)
        cout << "The full key has not been recovered. Please add more ciphertexts." << endl;

    cout << "The recovered key is " << recovered_key << endl;
}

int main()
{
    int NA = 100; // Number of attacks
    ui64 anal_avg_single[8][N];
    ui64 anal_avg_multi[8][N];
    for (int i = 0; i < 8; i++)
            for (int j = 0; j < N; j++) {
                anal_avg_multi[i][j] = 0;
                anal_avg_single[i][j] = 0;
            }
    for (int a = 0; a < NA; a++)
    {
        ui64 inputs[N];
        ui64 analysis[8][N];

        // For all possible single faults
        for (int i = 0; i < 8; i++)
            for (int j = 0; j < N; j++)
                analysis[i][j] = 64;
        // Iterate through single faults in each S-Box
        for (int i = 0; i < 8; i++)
        {
            //TODO: Introduce fault in an ith S-Box
            //TODO: Vary v with the faulty index in ith S-Box
            attack(inputs, V_MASK >> i, analysis);
        }
        for (int l = 0; l < 8; l++)
            for (int m = 0; m < N; m++)
                anal_avg_single[l][m] += analysis[l][m];

        // For multiple faults
        for (int i = 0; i < 8; i++)
            for (int j = 0; j < N; j++)
                analysis[i][j] = 64;
        //TODO: Introduce a fault in all S-Boxes
        attack(inputs, 0xff, analysis);
        for (int l = 0; l < 8; l++)
            for (int m = 0; m < N; m++)
                anal_avg_multi[l][m] += analysis[l][m];
    }
    
    for (int l = 0; l < 8; l++)
        for (int m = 0; m < N; m++)
        {
            anal_avg_single[l][m] /= NA;
            anal_avg_multi[l][m] /= NA;
        }
    
    ofstream out1("Single.csv");
    for (auto &row : anal_avg_single)
    {
        for (auto col : row)
            out1 << col << ',';
        out1 << '\n';
    }

    ofstream out2("Multi.csv");  // Multpily 8 keyspaces for a graph
    for (auto &row : anal_avg_multi)
    {
        for (auto col : row)
            out2 << col << ',';
        out2 << '\n';
    }
    return 0;
}