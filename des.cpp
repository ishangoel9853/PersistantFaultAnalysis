#include "des.h"
#include <bits/stdc++.h>
// #include "des_key.h"
// #include "des_data.h"
// #include "des_lookup.h"

//#pragma GCC pop_options

#define N 100

ui64 v = 0x0000000000000000; // 48 bit representation of faulty indices in 8 S-Boxes.
ui8 L8_MASK = 0x80;
char SBOX_Faulty[8][64] =
    {
        {// S1
         13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
         1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
         7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
         2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11},
        {// S2
         13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
         1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
         7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
         2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11},
        {// S3
         13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
         1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
         7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
         2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11},
        {// S4
         13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
         1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
         7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
         2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11},
        {// S5
         13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
         1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
         7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
         2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11},
        {// S6
         13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
         1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
         7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
         2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11},
        {// S7
         13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
         1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
         7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
         2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11},
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

void attack(ui64 inputs[N], ui8 mask, int analysis[8][N])
{
    ui64 key = 0x00f981c293aa6b0d;

    DES des(key);
    DES_Faulty des_f(key);

    ui64 recovered_key = 0x0000000000000000;

    ui8 key_pos = 0x00; // Recovered key positions 6 bits at a time
    vector<ui64> keyspace[8];

    // Persistent Fault Analysis
    for (int i = 0; i < N; i++)
    {
        ui64 result = des.encrypt(inputs[i]);
        ui64 result_faulty = des_f.encrypt(inputs[i]);
        cout << "Input:   " << inputs[i] << endl;
        cout << "Correct: " << result << endl;
        cout << "Faulty:  " << result_faulty << endl;

        if (result_faulty != result)
            cout << "---------------------------------Hit the spot---------------------------------" << endl;
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
        ui64 KEY_MASK = 0xfc00000000000000;
        ui32 B_MASK = 0xf0000000;
        for (int j = 0; j < 8; j += 1)
        {
            if (!(key_pos ^ mask))
            {
                break;
            }
            if ((d_b & (B_MASK >> (j * 4))) && !(key_pos & (L8_MASK >> j)) && (mask & (L8_MASK >> j)))
            {
                analysis[j][i] = 1;
                recovered_key |= (KEY_MASK >> (j * 6)) & (a1 ^ v);
                key_pos |= (L8_MASK >> j);
                cout << "-----------------------------------------HIT-----------------------------------------" << endl;
                continue;
            }
            if (mask & (L8_MASK >> j))
            {
                if (find(keyspace[j].begin(), keyspace[j].end(), (KEY_MASK >> (j * 6)) & (a1 ^ v)) == keyspace[j].end())
                {
                    keyspace[j].push_back((KEY_MASK >> (j * 6)) & (a1 ^ v));
                    // analysis[j][i] = max(analysis[j][((i == 0) ? 0 : (i - 1))] - 1, 0);
                }
                analysis[j][i] = 64 - keyspace[j].size();
            }
        }
    }

    if (key_pos ^ mask)
        cout << "The full key has not been recovered. Please add more ciphertexts." << endl;

    cout << "The recovered key is " << recovered_key << endl;
}

int main()
{
    // int NA = 1; // Number of attacks
    // ui64 anal_avg_single[8][N];
    // ui64 anal_avg_multi[8][N];
    // for (int i = 0; i < 8; i++)
    //     for (int j = 0; j < N; j++)
    //     {
    //         anal_avg_multi[i][j] = 0;
    //         anal_avg_single[i][j] = 0;
    //     }
    // for (int a = 0; a < NA; a++)
    // {
    //     srand(time(0));
    //     ui64 inputs[N];
    //     for (int i = 0; i < N; i++)
    //     {
    //         inputs[i] = rand() % 18446744073709551615 + 1;
    //     }

    //     int analysis[8][N];

    //     // For all possible single faults
    //     for (int i = 0; i < 8; i++)
    //         for (int j = 0; j < N; j++)
    //             analysis[i][j] = 64;
    //     // Iterate through single faults in each S-Box
    //     for (int i = 0; i < 1; i++)
    //     {
    //         int i_t = rand() % 64;
    //         int t = rand() % 5 + 1;
    //         SBOX_Faulty[i][i_t] = (SBOX_Faulty[i][i_t] + t) % 16;
    //         v = i_t << (63 - (i * 8));
    //         attack(inputs, L8_MASK >> i, analysis);
    //         SBOX_Faulty[i][i_t] = (SBOX_Faulty[i][i_t] - t) % 16;
    //     }
    //     v = 0;
    //     for (int l = 0; l < 8; l++)
    //         for (int m = 0; m < N; m++)
    //             anal_avg_single[l][m] += analysis[l][m];

    //     // For multiple faults
    //     // for (int i = 0; i < 8; i++)
    //     // {
    //     //     int i_t = rand() % 64;
    //     //     int t = rand() % 5 + 1;
    //     //     SBOX_Faulty[i][i_t] = (SBOX_Faulty[i][i_t] + t) % 16;
    //     //     for (int j = 0; j < N; j++)
    //     //         analysis[i][j] = 64;
    //     // }
    //     // attack(inputs, 0xff, analysis);
    //     // for (int l = 0; l < 8; l++)
    //     //     for (int m = 0; m < N; m++)
    //     //         anal_avg_multi[l][m] += analysis[l][m];
    // }

    // for (int l = 0; l < 8; l++)
    //     for (int m = 0; m < N; m++)
    //     {
    //         anal_avg_single[l][m] /= NA;
    //         anal_avg_multi[l][m] /= NA;
    //     }

    // ofstream out1("Single.csv");
    // for (auto &row : anal_avg_single)
    // {
    //     for (auto col : row)
    //         out1 << col << ',';
    //     out1 << '\n';
    // }

    // ofstream out2("Multi.csv"); // Multiply 8 keyspaces for a graph
    // for (auto &row : anal_avg_multi)
    // {
    //     for (auto col : row)
    //         out2 << col << ',';
    //     out2 << '\n';
    // }
    
    ui64 input  = 0x9474B8E8C73BCA7D;
    ui64 key  = 0x1111111111111111;
    DES des(key);
    ui64 res = des.encrypt(input);
    cout<<"INPUT:  "<<input<<endl;
    cout<<"RESULT:  "<<res<<endl;
    DES_Faulty des_f(key);
    ui64 res_f = des_f.encrypt_Faulty(input);
    cout<<"RESULT_Faulty:  "<<res_f<<endl;


    return 0;
}