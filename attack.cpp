#include "des.h"
#include <bits/stdc++.h>
#include <random>

// Number of inputs
#define N 500
// Number of attacks
#define NA 100


// Library Used to Generate Randon Numbers With a Uniform Distribuation
#define WORD_MASK (0xffffffffffffffffull) // 64 Bit Word Mask
std::mt19937 rng;
std::uniform_int_distribution<uint64_t> uni_dist(0x0ull, WORD_MASK);


ui64 v = 0x0000000000000000ull; // 48 bit representation of faulty indices in 8 S-Boxes.
ui8 L8_MASK = 0x80;

// Faulty SBOX values to used no the simulated attack
char SBOX_Faulty[8][64];

/**
* Fault injected DES class Derived from "DES" class
* Contains the functions for Faulty DES Encryption using a user defined key.
* 
* DES_Faulty(ui64 key)                      DES_Faulty Constructor
* des_Faulty(ui64 inp, bool mode)           Driver function for faulty DES Encryption (Mode: True-Decryption False-Encryption)
* encrypt_Faulty(ui64 inp)                  Faulty DES encryption function(encrypt inp with key "key")
* des_func_Faulty(ui32 Right, ui64 key)     Function "f" that uses the faulty SBOX values
*/
class DES_Faulty : public DES
{
public:
    DES_Faulty(ui64 key);
    ui64 encrypt_Faulty(ui64 inp);
    ui64 des_Faulty(ui64 inp, bool mode);
    ui64 last_subkey();

protected:
    ui32 des_func_Faulty(ui32 Right, ui64 key);
};

DES_Faulty::DES_Faulty(ui64 key) : DES(key)
{
}

ui64 DES_Faulty::last_subkey()
{
    return sub_key[15];
}

ui64 DES_Faulty::encrypt_Faulty(ui64 inp)
{
    return des_Faulty(inp, false);
}

ui64 DES_Faulty::des_Faulty(ui64 inp, bool mode)
{
    // Applying initial permutation
    inp = i_perm(inp);

    // Splitting "inp" into two 32-bit parts
    ui32 Left = (ui32)(inp >> 32) & L64_MASK;
    ui32 Right = (ui32)(inp & L64_MASK);

    ui32 F;
    // 16 round Encryption
    for (ui8 i = 0; i < 16; i++)
    {
        if (i != 15)
        {
            if (mode)
                F = des_func(Right, sub_key[15 - i]);
            else
                F = des_func(Right, sub_key[i]);
        }
        else
        {
            if (mode)
                F = des_func_Faulty(Right, sub_key[15 - i]);
            else
                F = des_func_Faulty(Right, sub_key[i]);
        }

        feistel_round(Left, Right, F);
    }

    // Swapping Left & Right
    inp = (((ui64)Right) << 32) | (ui64)Left;
    // Applying final permutation
    return f_perm(inp);
}

ui32 DES_Faulty::des_func_Faulty(ui32 Right, ui64 key) // des_func(Right,k) function
{
    // applying expansion permutation to convert Right to 48-bits
    ui64 sbox_inp = 0;
    for (ui8 i = 0; i < 48; i++)
    {
        sbox_inp <<= 1;
        sbox_inp |= (ui64)((Right >> (32 - EXPANSION[i])) & LB32_MASK);
    }

    // XORing expanded Ri with Ki(round key)
    sbox_inp = sbox_inp ^ key;

    // Applying S-Boxes function and returning 32-bit data
    ui32 sbox_out = 0;
    for (ui8 i = 0; i < 8; i++)
    {
        // Finding Row no. from outer bits
        char row = (char)((sbox_inp & (0x0000840000000000 >> 6 * i)) >> (42 - 6 * i));
        row = (row >> 4) | (row & 0x01);

        // Finding Column no. from the middle 4 bits of input
        char column = (char)((sbox_inp & (0x0000780000000000 >> 6 * i)) >> (43 - 6 * i));

        sbox_out <<= 4;
        sbox_out |= (ui32)(SBOX_Faulty[i][16 * row + column] & 0x0f); //Using Fault injected S-Boxes
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

// A function to print the binary form of a 64 bit integer
int printBinary(ui64 n)
{
    for (int i = 0; i < 64; i++)
    {
        cout << ((n >> (63 - i)) & 1);
    }
    cout << endl;
    return 0;
}

/* 
Performs a multi fault PFA on the given des_f comparing with the correct ciphertext from des.
Faulty indices in SBOXs are given beforehand using mask and the remaining keyspace at each input will be stored in analysis.
Returns the input index at which the attack is completed.
*/
int attack(DES des, DES_Faulty des_f, ui64 inputs[N], ui8 mask, int analysis[8][N])
{
    ui64 recovered_key = 0x0000000000000000;  // The recovered 48bit key from the attack

    ui8 key_pos = 0x00;  // Recovered key positions 6 bits at a time

    vector<ui64> keyspace[8];  // Vectors of impossible keys for every SBOX

    int n;  // Input index at which the attack is completed.

    // Persistent Fault Analysis iterating over the given inputs
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

        ui32 a = before_fp & L64_MASK;  // Picking the last 32 bits of the permutaion inversed ciphertext
        // Applying expansion permutation to convert a to 48-bits
        ui64 a1 = 0;
        for (ui8 i = 0; i < 48; i++)
        {
            a1 <<= 1;
            a1 |= (ui64)((a >> (32 - EXPANSION[i])) & LB32_MASK);
        }

        ui32 d_b1 = (before_fp ^ before_fp_f) >> 32;  // Indicator of the difference of outputs from the round function

        // Constant to reverse the straight d-box permutation in the round function
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
        // Iterating over every SBOX
        for (int j = 0; j < 8; j += 1)
        {
            // Performing differing SBOX outputs, already discovered key, and checks of affected SBOX respectively (Strategy 1)
            if ((d_b & (B_MASK >> (j * 4))) && !(key_pos & (L8_MASK >> j)) && (mask & (L8_MASK >> j)))
            {
                analysis[j][i] = 1;  // The key is found
                recovered_key |= (KEY_MASK >> (j * 6)) & (a1 ^ v);  // Recovered SBOX key appended to the master recovered_key
                key_pos |= (L8_MASK >> j);  // Indicator of discovered key at SBOX
                n = i;  // Input index of key recovery, always keeps the latest index in case of multiple faults
                continue;
            }

            // Update the remaining keyspace at each input (Strategy 2)
            // Check for affected SBOX
            if (mask & (L8_MASK >> j)) 
            {
                // Check if key is already found
                if (analysis[j][((i == 0) ? 0 : (i - 1))] == 1)
                {
                    analysis[j][i] = 1;
                    continue;
                }
                // Update the list of impossible keys
                if (find(keyspace[j].begin(), keyspace[j].end(), (KEY_MASK >> (j * 6)) & (a1 ^ v)) == keyspace[j].end())
                {
                    keyspace[j].push_back((KEY_MASK >> (j * 6)) & (a1 ^ v));
                }
                analysis[j][i] = 64 - keyspace[j].size();
            }
        }
    }

    // Check if all faulty SBOX keys are recovered
    if (key_pos ^ mask)
        cout << "The full key has not been recovered. Please add more ciphertexts." << endl;

    cout << "Recovered key = ";
    printBinary(recovered_key);
    return n;
}

int main()
{
    // The Average Key space left after the queries (for analysis)
    ui64 anal_avg_single[8][N];
    ui64 anal_avg_multi[8][N];

    // Number of query at which we get the successful hit (for analysis)
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

    // Performing the attack NA times
    for (int a = 0; a < NA; a++)
    {
        // THE 56 BIT KEY
        ui64 key = uni_dist(rng) & 0xffffffffffffffull;
        DES des(key);
        DES_Faulty des_f(key);

        // Reset All Faulty SBOXs
        for (int i = 0; i < 8; i++)
        {
            for (int j = 0; j < 64; j++)
            {
                SBOX_Faulty[i][j] = SBOX[i][j];
            }
        }

        // Reset Remaining Key Space
        for (int i = 0; i < 8; i++)
            for (int j = 0; j < N; j++)
                analysis[i][j] = 64;

        int analysis[8][N];
        
        // Assigning random 64 bit inputs (Plain Text Bank)
        ui64 inputs[N];
        for (int i = 0; i < N; i++)
        {
            inputs[i] = uni_dist(rng);
        }

        cout << "\n\n************************************ ATTACK " << a + 1 << " ************************************\n\n"
             << endl;
        


        // The key under attack 
        cout << "Last Round Key:";
        printBinary(des_f.last_subkey());
        
        // For all possible single faults
        cout << "Single Faults--------------------------------------------------------------------" << endl;
        
        // Iterate through single faults in each S-Box
        for (int i = 0; i < 8; i++)
        {
            cout << "SBOX " << i + 1 << ":" << endl;
        
            // Mounting the Fault in the S-box randomly
            int i_t = uni_dist(rng) % 64;
            int t = uni_dist(rng) % 5 + 1;
            char row = (char)((i_t & 0x20) >> 4) | (i_t & 0x01);
            char column = (char)((i_t & 0x1e) >> 1);
            int index = 16 * row + column;  // Random index
            SBOX_Faulty[i][index] = (SBOX_Faulty[i][index] + t) % 16;  // Introducing a random fault in a random index of ith SBOX

            v = ((ui64)i_t) << (48 - ((i + 1) * 6));  // Updating location of faulty index

        
            ui64 q_no = attack(des, des_f, inputs, L8_MASK >> i, analysis);  // Performing the attack
            n_s[i][q_no]++;

            SBOX_Faulty[i][index] = (SBOX_Faulty[i][index] - t + 16) % 16;  // Resetting the fault
        }
        for (int l = 0; l < 8; l++)
            for (int m = 0; m < N; m++)
                anal_avg_single[l][m] += analysis[l][m];

        // For multiple faults
        v = 0;
        cout << "Multiple Faults------------------------------------------------------------------" << endl;
        
        // Mounting Fault in Each S-box
        for (int i = 0; i < 8; i++)
        {
            int i_t = uni_dist(rng) % 64;
            i_t = 63;
            int t = uni_dist(rng) % 5 + 1;

            char row = (char)((i_t & 0x20) >> 4) | (i_t & 0x01);
            char column = (char)((i_t & 0x1e) >> 1);
            int index = 16 * row + column;  // Random index
            SBOX_Faulty[i][index] = (SBOX_Faulty[i][index] + t) % 16;  // Introducing a random fault in a random index of ith SBOX

            v |= ((ui64)i_t) << (48 - ((i + 1) * 6));  // Updating location of faulty index

            for (int j = 0; j < N; j++)
                analysis[i][j] = 64;
        }
        ui64 q_no = attack(des, des_f, inputs, 0xff, analysis);  //  Performing the attack
        n_m[q_no]++;

        for (int l = 0; l < 8; l++)
            for (int m = 0; m < N; m++)
                anal_avg_multi[l][m] += analysis[l][m];
    }

    // Preparing the analysis outputs

    // Average number of inputs for single faults
    float avg_s[8] = {0};
    // Average number of inputs for multiple faults
    float avg_m = 0;

    // Averaging analysis over all attacks 
    for (int m = 0; m < N; m++)
    {
        avg_m += n_m[m] * (m + 1);

        for (int l = 0; l < 8; l++)
        {
            avg_s[l] += n_s[l][m] * (m + 1);
            anal_avg_single[l][m] /= NA;
            anal_avg_multi[l][m] /= NA;
        }
    }
    avg_m /= NA;

    for (int l = 0; l < 8; l++)
        avg_s[l] /= NA;

    // Exporting analysis of remaining keyspace at each input to a .csv file for single faults
    ofstream out1("KeySpace_Single.csv");
    for (auto &row : anal_avg_single)
    {
        for (auto col : row)
            out1 << log2(col) << ',';
        out1 << '\n';
    }

    // Exporting analysis of remaining keyspace at each input to a .csv file for multiple faults
    ofstream out2("KeySpace_Multi.csv");
    for (int i = 0; i < N; i++)
    {
        ui64 t = 1;
        for (int j = 0; j < 8; j++)
            t *= anal_avg_multi[j][i];
        out2 << log2(t) << ',';
    }

    // Exporting analysis of completed attacks at each input index to a .csv file for single faults
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

    // Exporting analysis of completed attacks at each input index to a .csv file for multiple faults
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