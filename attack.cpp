#include "des.h"
#include <bits/stdc++.h>
#include <random>
// #include "des_key.h"
// #include "des_data.h"
// #include "des_lookup.h"

//#pragma GCC pop_options

// Library Used to Generate Randon Numbers With a Uniform Distribuation
#define WORD_MASK (0xffffffffffffffffull) // 64 Bit Word Mask
std::mt19937 rng;
std::uniform_int_distribution<uint64_t> uni_dist(0x0ull, WORD_MASK);


// Number of inputs
#define N 500
// Number of attacks
#define NA 100

ui64 v = 0x0000000000000000ull; // 48 bit representation of faulty indices in 8 S-Boxes.
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
    ui64 last_subkey();

protected:
    ui32 f_Faulty(ui32 R, ui64 k);
};

DES_Faulty::DES_Faulty(ui64 key) : DES(key)
{
}

ui64 DES_Faulty::last_subkey()
{
    return sub_key[15];
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


int printBinary(ui64 n)
{
    for (int i = 0; i < 64; i++)
    {
        cout << ((n >> (63 - i)) & 1);
    }
    cout << endl;
    return 0;
}

int attack(DES des, DES_Faulty des_f, ui64 inputs[N], ui8 mask, int analysis[8][N])
{
    ui64 recovered_key = 0x0000000000000000;

    ui8 key_pos = 0x00; // Recovered key positions 6 bits at a time
    vector<ui64> keyspace[8];
    int n;
    // Persistent Fault Analysis
    for (int i = 0; i < N; i++)
    {
        ui64 result = des.encrypt(inputs[i]);
        ui64 result_faulty = des_f.encrypt_Faulty(inputs[i]);

        // Reverse final permutation for ciphertexts
        ui64 before_fp_f = 0;
        ui64 before_fp = 0;
        for (ui8 i = 0; i < 64; i++)
        {
            before_fp <<= 1;
            before_fp_f <<= 1;
            before_fp |= (result >> (64 - IP[i])) & LB64_MASK;
            before_fp_f |= (result_faulty >> (64 - IP[i])) & LB64_MASK;
        }

        ui32 a = before_fp & L64_MASK;
        // Applying expansion permutation to convert a to 48-bits
        ui64 a1 = 0;
        for (ui8 i = 0; i < 48; i++)
        {
            a1 <<= 1;
            a1 |= (ui64)((a >> (32 - EXPANSION[i])) & LB32_MASK);
        }

        ui32 d_b1 = (before_fp ^ before_fp_f) >> 32;
        static const char PBOXI[] =
            {
                9, 17, 23, 31,
                13, 28, 2, 18,
                24, 16, 30, 6,
                26, 20, 10, 1,
                8, 14, 25, 3,
                4, 29, 11, 19,
                32, 12, 22, 7,
                5, 27, 15, 21};
        // Reverse f straight d-box permutation
        ui32 d_b = 0;
        for (ui8 i = 0; i < 32; i++)
        {
            d_b <<= 1;
            d_b |= (d_b1 >> (32 - PBOXI[i])) & LB32_MASK;
        }
        ui64 KEY_MASK = 0x0000fc0000000000;
        ui32 B_MASK = 0xf0000000;
        for (int j = 0; j < 8; j += 1)
        {
            if ((d_b & (B_MASK >> (j * 4))) && !(key_pos & (L8_MASK >> j)) && (mask & (L8_MASK >> j)))
            {
                analysis[j][i] = 1;
                recovered_key |= (KEY_MASK >> (j * 6)) & (a1 ^ v);
                key_pos |= (L8_MASK >> j);
                n = i;
                continue;
            }
            if (mask & (L8_MASK >> j))
            {
                if (analysis[j][((i == 0) ? 0 : (i - 1))] == 1)
                {
                    analysis[j][i] = 1;
                    continue;
                }
                if (find(keyspace[j].begin(), keyspace[j].end(), (KEY_MASK >> (j * 6)) & (a1 ^ v)) == keyspace[j].end())
                {
                    keyspace[j].push_back((KEY_MASK >> (j * 6)) & (a1 ^ v));
                }
                analysis[j][i] = 64 - keyspace[j].size();
            }
        }
    }

    if (key_pos ^ mask)
        cout << "The full key has not been recovered. Please add more ciphertexts." << endl;

    cout << "Recovered key = ";
    printBinary(recovered_key);
    return n;
}

int main()
{
    // The Average Key space left after the queries
    ui64 anal_avg_single[8][N];
    ui64 anal_avg_multi[8][N];
    
    // Number of query at which we get the successful hit
    ui64 n_s[8][N];
    ui64 n_m[N];

    for (int i = 0; i < 8; i++)
        for (int j = 0; j < N; j++)
        {
            anal_avg_multi[i][j] = 0;
            anal_avg_single[i][j] = 0;
            n_s[i][j] = 0;
            n_m[j] = 0;
        }


    for (int a = 0; a < NA; a++)
    {
        // THE 56 BIT KEY
        ui64 key = uni_dist(rng) & 0xffffffffffffffull;
        DES des(key);
        DES_Faulty des_f(key);
        // Reset All Faulty SBOX
        for (int i=0;i<8;i++)
        {
            for(int j=0;j<64;j++)
            {
                SBOX_Faulty[i][j] = SBOX[i][j];
            }
        }

        cout << "\n\n************************************ ATTACK " << a + 1 << " ************************************\n\n"
             << endl;
        ui64 inputs[N];
        for (int i = 0; i < N; i++)
        {
            inputs[i] = uni_dist(rng);
        }

        int analysis[8][N];

        cout<<"Key:";
        printBinary(des_f.last_subkey());
        // For all possible single faults
        cout << "Single Faults--------------------------------------------------------------------" << endl;
        for (int i = 0; i < 8; i++)
            for (int j = 0; j < N; j++)
                analysis[i][j] = 64;
        // Iterate through single faults in each S-Box
        for (int i = 0; i < 8; i++)
        {
            cout << "SBOX " << i + 1 << ":" << endl;
            int i_t = uni_dist(rng) % 64;
            int t = uni_dist(rng) % 5 + 1;

            char row = (char)((i_t & 0x20) >> 4) | (i_t & 0x01);
            char column = (char)((i_t & 0x1e) >> 1);
            int index = 16 * row + column;
            SBOX_Faulty[i][index] = (SBOX_Faulty[i][index] + t) % 16;
            
            v = ((ui64)i_t) << (48 - ((i+1) * 6));
            
            ui64 q_no = attack(des, des_f, inputs, L8_MASK >> i, analysis);
            n_s[i][q_no]++;

            SBOX_Faulty[i][index] = (SBOX_Faulty[i][index] - t + 16) % 16;
        }
        for (int l = 0; l < 8; l++)
            for (int m = 0; m < N; m++)
                anal_avg_single[l][m] += analysis[l][m];

        // For multiple faults
        v = 0;
        cout << "Multiple Faults------------------------------------------------------------------" << endl;
        for (int i = 0; i < 8; i++)
        {
            int i_t = uni_dist(rng) % 64;
            i_t = 63;
            int t = uni_dist(rng) % 5 + 1;
            
            char row = (char)((i_t & 0x20) >> 4) | (i_t & 0x01);
            char column = (char)((i_t & 0x1e) >> 1);
            int index = 16 * row + column;
            SBOX_Faulty[i][index] = (SBOX_Faulty[i][index] + t) % 16;
            
            v |= ((ui64)i_t) << (48 - ((i+1) * 6));

            for (int j = 0; j < N; j++)
                analysis[i][j] = 64;
        }
        ui64 q_no = attack(des, des_f, inputs, 0xff, analysis);
        n_m[q_no]++;

        for (int l = 0; l < 8; l++)
            for (int m = 0; m < N; m++)
                anal_avg_multi[l][m] += analysis[l][m];
    }

    float avg_s[8] = {0};
    float avg_m = 0;

    for (int m = 0; m < N; m++)
    {
        avg_m += n_m[m] * (m+1);

        for (int l = 0; l < 8; l++)
        {
            avg_s[l] += n_s[l][m] * (m+1);
            anal_avg_single[l][m] /= NA;
            anal_avg_multi[l][m] /= NA;
        }
    }
    avg_m /= NA;

    for (int l=0; l < 8; l++)
        avg_s[l] /= NA;
        

    ofstream out1("KeySpace_Single.csv");
    for (auto &row : anal_avg_single)
    {
        for (auto col : row)
            out1 << log2(col) << ',';
        out1 << '\n';
    }

    ofstream out2("KeySpace_Multi.csv");
    for (int i = 0; i < N; i++)
    {
        ui64 t = 1;
        for (int j = 0; j < 8; j++)
            t *= anal_avg_multi[j][i];
        out2 << log2(t) << ',';
    }

    ofstream out3("NumberOfSolved_Single.csv");
    for (auto &row : n_s)
    {
        ui64 t = 0;
        for (auto col : row)
        {
            t += col;
            out3 << t << ',';
        }
        out3 << '\n';
    }

    ofstream out4("NumberOfSolved_Multi.csv");
    ui64 t = 0;
    for (int i = 0; i < N; i++)
    {
        t += n_m[i]; 
        out4 << t << ',';
    }


    cout << "\n\nFor single faults, average querys required: " << endl;
    for (int i = 0; i < 8; i++)
        cout << "SBOX " << i + 1 << ": " << avg_s[i] << endl;
    cout << "For multiple faults, average queries required: " << avg_m << endl;

    return 0;
}