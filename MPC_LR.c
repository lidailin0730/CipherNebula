/*
 ============================================================================
 Name        : Combined_MPC_SHA.c
 Author      : Combined from previous code sources
 Version     : 0.1
 Description : Combined MPC SHA1 and related operations
 ============================================================================
 */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <gmp.h>
#include "shared.h"
#include "omp.h"
#include </usr/local/include/pbc/pbc.h>
#include </usr/local/include/pbc/pbc_test.h>


#define CH(e,f,g) ((e & f) ^ ((~e) & g))

// LCG parameters 1
#define MULTIPLIER_1 22695477
#define INCREMENT_1 1
#define MODULUS_1 2147483648   // 2^31

// LCG parameters 2
#define MULTIPLIER_2 22695477
#define INCREMENT_2 1
#define MODULUS_2 2147483648   // 2^31

// LCG parameters 3
#define MULTIPLIER_3 1103515245
#define INCREMENT_3 12345
#define MODULUS_3 2147483647   // A prime number

#define lwe_q 4096

//
int totalRandom = 0;
int totalSha = 0;
int totalSS = 0;
int totalHash = 0;

// Function to generate a 32-bit random number
// Generate a 32-bit random number by combining four 8-bit random numbers
uint32_t rand32() {
    uint32_t x;
    x = rand() & 0xff;
    x |= (rand() & 0xff) << 8;
    x |= (rand() & 0xff) << 16;
    x |= (rand() & 0xff) << 24;

    return x;
}

// Function to print the binary representation of a 32-bit number
// Print the binary representation of a 32-bit number recursively
void printbits(uint32_t n) {
    if (n) {
        printbits(n >> 1);
        printf("%d", n & 1);
    }
}

// Function to print the shares array
// Print the shares array, showing each round's values
void print_shares(uint32_t shares[NUM_ROUNDS][4], const char* array_name) {
    printf("\nPrinting %s array:\n", array_name);
    for (int k = 0; k < NUM_ROUNDS; k++) {
        printf("Round %d: ", k);
        for (int j = 0; j < 4; j++) {
            printf("%u ", shares[k][j]);
        }
        printf("\n");
    }
}

// Function to generate a random number in the ZP group
// Generate a random number in the ZP group by seeding the random number generator
uint32_t Ra(uint32_t x) {
    srand(x);
    return rand() % (MODULUS_1/10); // Randomly generate a number in the ZP group
}

// Function to perform MPC XOR operation
// Perform the MPC XOR operation on two arrays and store the result in a third array
void mpc_XOR(uint32_t x[5], uint32_t y[5], uint32_t z[5]) {
    z[0] = x[0] ^ y[0];
    z[1] = x[1] ^ y[1];
    z[2] = x[2] ^ y[2];
    z[3] = x[3] ^ y[3];
    z[4] = x[4] ^ y[4];
}

// Function to perform MPC AND operation
// Perform the MPC AND operation on two arrays and store the result in a third array
void mpc_AND(uint32_t x[5], uint32_t y[5], uint32_t z[5], uint32_t *randomness[3], int* randCount, View views[5], int* countY) {
    // Generate three random numbers
    uint32_t r[3] = { getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount), getRandom32(randomness[2], *randCount)};
    *randCount += 4;
    uint32_t t[5] = { 0 };

    t[0] = (x[0] & y[1]) ^ (x[1] & y[0]) ^ (x[2] & y[3]) ^ (x[0] & y[2]) ^ (x[0] & y[0]) ^ r[0] ^ r[1];
    t[1] = (x[1] & y[2]) ^ (x[2] & y[1]) ^ (x[3] & y[1]) ^ (x[4] & y[0]) ^ (x[1] & y[1]) ^ r[1] ^ r[2];
    t[2] = (x[2] & y[4]) ^ (x[3] & y[2]) ^ (x[4] & y[1]) ^ (x[3] & y[4]) ^ (x[2] & y[2]) ^ r[2] ^ r[0];
    t[3] = (x[3] & y[0]) ^ (x[4] & y[3]) ^ (x[0] & y[3]) ^ (x[1] & y[3]) ^ (x[3] & y[3]);
    t[4] = (x[4] & y[2]) ^ (x[0] & y[4]) ^ (x[1] & y[4]) ^ (x[2] & y[0]) ^ (x[4] & y[4]);

    z[0] = t[0];
    z[1] = t[1];
    z[2] = t[2];
    z[3] = t[3];
    z[4] = t[4];
    views[0].y[*countY] = z[0];
    views[1].y[*countY] = z[1];
    views[2].y[*countY] = z[2];
    views[3].y[*countY] = z[3];
    views[4].y[*countY] = z[4];
    (*countY)++;
}

// Function to perform MPC NEGATE operation
// Perform the MPC NEGATE operation on an array and store the result in another array
void mpc_NEGATE(uint32_t x[5], uint32_t z[5]) {
    z[0] = ~x[0];
    z[1] = ~x[1];
    z[2] = ~x[2];
    z[3] = ~x[3];
    z[4] = ~x[4];
}

// Function to perform MPC ADD operation
// Perform the MPC ADD operation on two arrays and store the result in a third array
void mpc_ADD(uint32_t x[4], uint32_t y[4], uint32_t z[4], uint32_t *randomness[3], int* randCount, View views[4], int* countY) {
    uint32_t c[5] = { 0 };
    uint32_t r[3] = { getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount), getRandom32(randomness[2], *randCount)};
    *randCount += 4;

    uint8_t a[5], b[5];
    uint8_t t;

    for(int i = 0; i < 31; i++) { // Bitwise addition for 32 bits
        for (int j = 0; j < 5; j++) {
            a[j] = GETBIT(x[j] ^ c[j], i);
            b[j] = GETBIT(y[j] ^ c[j], i);
        }
        t = (a[0]&b[1]) ^ (a[1]&b[0]) ^ (a[1]&b[4]) ^ (a[1]&b[3]) ^ GETBIT(r[0],i);
        SETBIT(c[0],i+1, t ^ (a[0]&b[0]) ^ GETBIT(c[0],i) ^ GETBIT(r[1],i));

        t = (a[1]&b[2]) ^ (a[2]&b[1]) ^ (a[3]&b[1]) ^ (a[4]&b[1]) ^ GETBIT(r[1],i);
        SETBIT(c[1],i+1, t ^ (a[1]&b[1]) ^ GETBIT(c[1],i) ^ GETBIT(r[2],i));

        t = (a[2]&b[3]) ^ (a[3]&b[2]) ^ (a[2]&b[0]) ^ (a[2]&b[4]) ^ GETBIT(r[2],i);
        SETBIT(c[2],i+1, t ^ (a[2]&b[2]) ^ GETBIT(c[2],i) ^ GETBIT(r[0],i));

        t = (a[3]&b[4]) ^ (a[4]&b[3]) ^ (a[0]&b[3]) ^ (a[0]&b[2]);
        SETBIT(c[3],i+1, t ^ (a[3]&b[3]) ^ GETBIT(c[3],i));
    }

    z[0] = x[0] ^ y[0] ^ c[0];
    z[1] = x[1] ^ y[1] ^ c[1];
    z[2] = x[2] ^ y[2] ^ c[2];
    z[3] = x[3] ^ y[3] ^ c[3];
    z[4] = x[4] ^ y[4] ^ c[4];

    views[0].y[*countY] = c[0];
    views[1].y[*countY] = c[1];
    views[2].y[*countY] = c[2];
    views[3].y[*countY] = c[3];
    views[4].y[*countY] = c[4];
    *countY += 1;
}

// Function to perform MPC ADDK operation
// Perform the MPC ADDK operation, adding a scalar to an array and storing the result in another array
void mpc_ADDK(uint32_t x[4], uint32_t y, uint32_t z[4], uint32_t *randomness[3], int* randCount, View views[4], int* countY) {
    uint32_t c[4] = {0};  // Initialize carry to 0
    uint32_t r[3] = {getRandom32(randomness[0], *randCount), 
                     getRandom32(randomness[1], *randCount), 
                     getRandom32(randomness[2], *randCount)};
    *randCount += 4;  // Update the random number count

    uint8_t a[4], b[4];
    uint8_t t;
    for (int i = 0; i < 31; i++) {
        for (int j = 0; j < 5; j++) {
            a[j] = GETBIT(x[j] ^ c[j], i);
            b[j] = GETBIT(y ^ c[j], i);
        }
        t = (a[0]&b[1]) ^ (a[1]&b[0]) ^ (a[2]&b[4]) ^ (a[3]&b[2]) ^ GETBIT(r[0],i);
        SETBIT(c[0],i+1, t ^ (a[0]&b[0]) ^ GETBIT(c[0],i) ^ GETBIT(r[1],i));

        t = (a[1]&b[2]) ^ (a[2]&b[1]) ^ (a[3]&b[1]) ^ (a[4]&b[2]) ^ GETBIT(r[1],i);
        SETBIT(c[1],i+1, t ^ (a[1]&b[1]) ^ GETBIT(c[1],i) ^ GETBIT(r[2],i));

        t = (a[2]&b[3]) ^ (a[3]&b[4]) ^ (a[4]&b[1]) ^ (a[0]&b[3]) ^ GETBIT(r[2],i);
        SETBIT(c[2],i+1, t ^ (a[2]&b[2]) ^ GETBIT(c[2],i) ^ GETBIT(r[0],i));

        t = (a[3]&b[0]) ^ (a[4]&b[3]) ^ (a[0]&b[2]) ^ (a[1]&b[3]);
        SETBIT(c[3],i+1, t ^ (a[3]&b[3]) ^ GETBIT(c[3],i));
    }

    // Calculate the final result
    for (int i = 0; i < 4; i++) {
        z[i] = x[i] ^ y ^ c[i];
        views[i].y[*countY] = c[i];
    }
    *countY += 1;
}

// Function to perform SHA1 hash calculation
// Perform the SHA1 hash calculation on the input data and store the result
int sha1(uint32_t* result_add,  int numBits) {
    uint32_t hA[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476,
                       0xC3D2E1F0};
    if (numBits > 447) {
        printf("Input too long, aborting!");
        return -1;
    }
    int chars = numBits >> 3;
    uint32_t* chunk = calloc(64, 1); // 512 bits

    chunk[chars] = 0x80;
    // Last 8 chars used for storing the length of the input without padding, in big-endian.
    // Since we only care for one block, we are safe with just using the last 9 bits and 0'ing the rest
    chunk[62] = numBits >> 8;
    chunk[63] = numBits;

    uint32_t w[80];
    int i;
    for (i = 0; i < 16; i++) {
        w[i] = (chunk[i * 4] << 24) | (chunk[i * 4 + 1] << 16)| (chunk[i * 4 + 2] << 8) | chunk[i * 4 + 3];
    }

    for (i = 16; i < 80; i++) {
        w[i] = LEFTROTATE((w[i - 3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1);
        printf("W[%d]: %02X\n", i, w[i]);
    }

    uint32_t a, b, c, d, e, f, k, temp;
    a = hA[0];
    b = hA[1];
    c = hA[2];
    d = hA[3];
    e = hA[4];

    for (i = 0; i < 80; i++) {
        if(i <= 19) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        }
        else if(i <= 39) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        }
        else if(i <= 59) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        }
        else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }
        printf("F[%d]: %04X\n", i, f);

        temp = (LEFTROTATE(a,5))+f+e+k+w[i];
        e = d;
        d = c;
        c = LEFTROTATE(b,30);
        b = a;
        a = temp;
    }

    hA[0] += a;
    hA[1] += b;
    hA[2] += c;
    hA[3] += d;
    hA[4] += e;

    for (i = 0; i < 5; i++) {
        result_add[i * 4] = (hA[i] >> 24);
        result_add[i * 4 + 1] = (hA[i] >> 16);
        result_add[i * 4 + 2] = (hA[i] >> 8);
        result_add[i * 4 + 3] = hA[i];
    }
    return 0;
}

// Function to perform MPC RIGHTROTATE operation
// Perform the MPC RIGHTROTATE operation on an array and store the result in another array
void mpc_RIGHTROTATE(uint32_t x[], int i, uint32_t z[]) {
    z[0] = RIGHTROTATE(x[0], i);
    z[1] = RIGHTROTATE(x[1], i);
    z[2] = RIGHTROTATE(x[2], i);
    z[3] = RIGHTROTATE(x[3], i);
    z[4] = RIGHTROTATE(x[4], i);
}

// Function to perform MPC LEFTROTATE operation
// Perform the MPC LEFTROTATE operation on an array and store the result in another array
void mpc_LEFTROTATE(uint32_t x[], int i, uint32_t z[]) {
    z[0] = LEFTROTATE(x[0], i);
    z[1] = LEFTROTATE(x[1], i);
    z[2] = LEFTROTATE(x[2], i);
    z[3] = LEFTROTATE(x[3], i);
    z[4] = LEFTROTATE(x[4], i);
}

// Function to perform MPC RIGHTSHIFT operation
// Perform the MPC RIGHTSHIFT operation on an array and store the result in another array
void mpc_RIGHTSHIFT(uint32_t x[5], int i, uint32_t z[5]) {
    z[0] = x[0] >> i;
    z[1] = x[1] >> i;
    z[2] = x[2] >> i;
    z[3] = x[3] >> i;
    z[4] = x[4] >> i;
}

// Function to perform MPC MAJ operation
// Perform the MPC MAJ operation on three arrays and store the result in another array
void mpc_MAJ(uint32_t a[], uint32_t b[5], uint32_t c[5], uint32_t z[5], unsigned char randomness[3][1472], int* randCount, View views[5], int* countY) {
    uint32_t t0[5];
    uint32_t t1[5];

    mpc_XOR(a, b, t0);
    mpc_XOR(a, c, t1);

    // mpc_AND(t0, t1, z, randomness, randCount, views, countY);
    mpc_XOR(z, a, z);
}

// Function to perform MPC CH operation
// Perform the MPC CH operation on three arrays and store the result in another array
void mpc_CH(uint32_t e[], uint32_t f[4], uint32_t g[4], uint32_t z[4], unsigned char randomness[3][1472], int* randCount, View views[4], int* countY) {
    uint32_t t0[4];
    // Alternative, rewritten as e & (f^g) ^ g
    mpc_XOR(f,g,t0);
    mpc_AND(e,t0,t0, randomness, randCount, views, countY);
    mpc_XOR(t0,g,z);
}

// Function to perform MPC MULK operation
// Perform the MPC MULK operation, multiplying an array by a scalar and storing the result in another array
void mpc_MULK(uint32_t x[4], uint32_t y, uint32_t z[4], View views[4], int* countY) {
    // Perform scalar multiplication directly, multiplying each x[i] by the scalar
    for (int i = 0; i < 4; i++) {
        z[i] = x[i] * y;  // Perform scalar multiplication
        views[i].y[*countY] = z[i];   // Save the multiplication result to the view
    }
    *countY += 1;
}

// Complex random number generation function, mixing multiple LCGs and increasing complexity
// Generate a complex random number using the LCG algorithm
uint32_t rand_complex(uint32_t new_seed) {
    // Use LCG1
    uint32_t r1 = (MULTIPLIER_1 * new_seed + INCREMENT_1) % MODULUS_1;

    return r1;
}

// Function to generate MPC random numbers
// Generate MPC random numbers based on the input seed and randomness
uint32_t mpc_rand(uint32_t results[4],uint32_t new_seed[4],  unsigned char *randomness[3], View views[4], int* countY) {
    uint32_t seed[4];
    uint32_t temp[4];

    for (int i = 0; i < 4; i++) {
        seed[i] = new_seed[i];
    }
    mpc_MULK(seed,MULTIPLIER_1,temp, views, countY);

    for (int i = 0; i < 4; i++) {
        results[i] = temp[i]+(INCREMENT_1/4);
    }
    mpc_MULK(seed,MULTIPLIER_1,results, views, countY);
    return 0;
}

// Function to perform MPC SHA1 hash calculation
// Perform the MPC SHA1 hash calculation on the input data and store the result
int mpc_sha1(uint32_t* results[4], uint32_t* inputs[4], int numBits, uint32_t *randomness[3], View views[4], int* countY) {
    if (numBits > 447) {
        printf("Input too long, aborting!");
        return -1;
    }

    int* randCount = calloc(1, sizeof(int));
    int chars = numBits >> 3; // Convert the number of bits to bytes by dividing by 8
    uint32_t* chunks[5];
    uint32_t w[80][5];
    for (int i = 0; i < 5; i++) {
        chunks[i] = calloc(64, 1); // 512 bits
        memcpy(chunks[i], inputs[i], chars);

        chunks[i][chars] = 0x80;
        // Last 8 chars used for storing the length of the input without padding, in big-endian.
        // Since we only care for one block, we are safe with just using the last 9 bits and 0'ing the rest
        chunks[i][62] = numBits >> 8;
        chunks[i][63] = numBits;
        // The first 16 groups are formed by splitting the message
        for (int j = 0; j < 16; j++) {
            // Combine four 8-bit bytes into a 32-bit word.
            w[j][i] = (chunks[i][j * 4] << 24) | (chunks[i][j * 4 + 1] << 16)| (chunks[i][j * 4 + 2] << 8) | chunks[i][j * 4 + 3];
        }
        printf("Chars: %d\n", chars);
        free(chunks[i]);
    }
    // The last 16 - 80 groups are calculated from the first 16 groups
    uint32_t temp[5];
    uint32_t t0[5];
    for (int j = 16; j < 80; j++) {
        mpc_XOR(w[j-3], w[j-8], temp);
        mpc_XOR(temp, w[j-14], temp);
        mpc_XOR(temp, w[j-16], temp);
        mpc_LEFTROTATE(temp,1,w[j]);

        printf("W[%d]: %02X\n", j, w[j][0]^w[j][1]^w[j][2]^w[j][3]^w[j][4]);
    }

    uint32_t a[5] = { hA[0],hA[0],hA[0],hA[0],hA[0] };
    uint32_t b[5] = { hA[1],hA[1],hA[1],hA[1],hA[1] };
    uint32_t c[5] = { hA[2],hA[2],hA[2],hA[2],hA[2] };
    uint32_t d[5] = { hA[3],hA[3],hA[3],hA[3],hA[3] };
    uint32_t e[5] = { hA[4],hA[4],hA[4],hA[4],hA[4] };
    uint32_t f[5];
    uint32_t k;
    for (int i = 0; i < 80; i++) {
        if(i <= 19) {
            // f = d ^ (b & (c ^ d))
            mpc_XOR(c,d,f);
            mpc_AND(b, f, f, randomness, randCount, views, countY);
            mpc_XOR(d,f,f);
            k = 0x5A827999;
        }
        else if(i <= 39) {
            mpc_XOR(b,c,f);
            mpc_XOR(d,f,f);
            k = 0x6ED9EBA1;
        }
        else if(i <= 59) {
            // f = MAJ(b,c,d)
            mpc_MAJ(b,c,d,f,randomness, randCount, views, countY);
            k = 0x8F1BBCDC;
        }
        else {
            mpc_XOR(b,c,f);
            mpc_XOR(d,f,f);
            k = 0xCA62C1D6;
        }

        // temp = (a leftrotate 5) + f + e + k + w[i]
        mpc_LEFTROTATE(a,5,temp);
        mpc_ADD(f,temp,temp,randomness, randCount, views, countY);
        mpc_ADD(e,temp,temp,randomness, randCount, views, countY);
        mpc_ADDK(temp,k,temp,randomness, randCount, views, countY);
        mpc_ADD(w[i],temp,temp,randomness, randCount, views, countY);

        memcpy(e, d, sizeof(uint32_t) * 5);
        memcpy(d, c, sizeof(uint32_t) * 5);
        mpc_LEFTROTATE(b,30,c);
        memcpy(b, a, sizeof(uint32_t) * 5);
        memcpy(a, temp, sizeof(uint32_t) * 5);
    }

    uint32_t hHa[5][5] = { { hA[0],hA[0],hA[0],hA[0] ,hA[0] }, { hA[1],hA[1],hA[1],hA[1] ,hA[1]}, { hA[2],hA[2],hA[2],hA[2],hA[2] }, { hA[3],hA[3],hA[3],hA[3],hA[3] },
                           { hA[4],hA[4],hA[4],hA[4],hA[4] }};
    mpc_ADD(hHa[0], a, hHa[0], randomness, randCount, views, countY);
    mpc_ADD(hHa[1], b, hHa[1], randomness, randCount, views, countY);
    mpc_ADD(hHa[2], c, hHa[2], randomness, randCount, views, countY);
    mpc_ADD(hHa[3], d, hHa[3], randomness, randCount, views, countY);
    mpc_ADD(hHa[4], e, hHa[4], randomness, randCount, views, countY);

    for (int i = 0; i < 5; i++) {
        mpc_RIGHTSHIFT(hHa[i], 24, t0);
        results[0][i * 4] = t0[0];
        results[1][i * 4] = t0[1];
        results[2][i * 4] = t0[2];
        results[3][i * 4] = t0[3];
        results[4][i * 4] = t0[4];
        mpc_RIGHTSHIFT(hHa[i], 16, t0);
        results[0][i * 4 + 1] = t0[0];
        results[1][i * 4 + 1] = t0[1];
        results[2][i * 4 + 1] = t0[2];
        results[3][i * 4 + 1] = t0[3];
        results[4][i * 4 + 1] = t0[4];
        mpc_RIGHTSHIFT(hHa[i], 8, t0);
        results[0][i * 4 + 2] = t0[0];
        results[1][i * 4 + 2] = t0[1];
        results[2][i * 4 + 2] = t0[2];
        results[3][i * 4 + 2] = t0[3];
        results[4][i * 4 + 2] = t0[4];

        results[0][i * 4 + 3] = hHa[i][0];
        results[1][i * 4 + 3] = hHa[i][1];
        results[2][i * 4 + 3] = hHa[i][2];
        results[3][i * 4 + 3] = hHa[i][3];
        results[4][i * 4 + 3] = hHa[i][4];
    }
    return 0;
}

// Function to write data to a file
// Write the specified data to a binary file
int writeToFile(char filename[], void* data, int size, int numItems) {
    FILE *file;

    file = fopen(filename, "wb");
    if (!file) {
        printf("Unable to open file!");
        return 1;
    }
    fwrite(data, size, numItems, file);
    fclose(file);
    return 0;
}

// Function to create a commitment
// Create a commitment using the shares, randomness, and views
a commit(uint32_t shares[4], unsigned char *randomness[3], uint32_t rs[3][4], View views[4]) {
    uint32_t inputs[4];
    inputs[0] = shares[0];
    inputs[1] = shares[1];
    inputs[2] = shares[2];
    inputs[3] = shares[3];
    uint32_t results[4];

    int* countY = calloc(1, sizeof(int));
    mpc_rand(results, inputs, randomness, views, countY);

    // Explicitly add y to view
    views[0].y[*countY] = results[0];
    views[1].y[*countY] = results[1];
    views[2].y[*countY] = results[2];
    views[3].y[*countY] = results[3];
    (*countY)++;

    a a;
    a.yp[0] = results[0];
    a.yp[1] = results[1];
    a.yp[2] = results[2];
    a.yp[3] = results[3];
    return a;
}

// Function to generate a proof object
// Generate a proof object using the challenge, keys, randomness, and views
z prove(int e, unsigned char keys[3][16], unsigned char rs[3][4], View views[4]) {
    z z;
    memcpy(z.ke, keys[e], 16);
    memcpy(z.ke1, keys[(e + 1) % 3], 16);

    // Provide two out of the first three views
    z.ve = views[e];
    z.ve1 = views[(e + 1) % 3];

    // The fourth view is public
    z.ve3 = views[3];

    memcpy(z.re, rs[e], 4);
    memcpy(z.re1, rs[(e + 1) % 3], 4);

    return z;
}

// Signal handler function
// Handle signals and exit gracefully
void signal_handler(int signal) {
    printf("Caught signal %d\n", signal);
    exit(1);
}

// Main ZKLR function
// Execute the Zero-Knowledge Blind Output Operation
void ZKLR(uint32_t shares[NUM_ROUNDS][4], uint32_t shares_x) {
    setbuf(stdout, NULL);
    srand((unsigned) time(NULL));
    init_EVP();
    openmp_thread_setup();

    unsigned char garbage[4];
    if (RAND_bytes(garbage, 4) != 1) {
        printf("RAND_bytes failed crypto, aborting\n");
        return;
    }

    // Initialization
    clock_t begin = clock(), delta, deltaA;
    unsigned char rs[NUM_ROUNDS][3][4]; // Random numbers for each party's commitment
    unsigned char keys[NUM_ROUNDS][3][16]; // Keys for each round
    a as[NUM_ROUNDS]; // Commitments for each round
    View localViews[NUM_ROUNDS][4]; // Local views for each round
    int totalCrypto = 0;

    // Generate random keys
    clock_t beginCrypto = clock(), deltaCrypto;
    if (RAND_bytes(keys, NUM_ROUNDS * 3 * 16) != 1) {
        printf("RAND_bytes failed crypto, aborting\n");
        return;
    }

    // Generate random numbers for commitments
    if (RAND_bytes(rs, NUM_ROUNDS * 3 * 4) != 1) {
        printf("RAND_bytes failed crypto, aborting\n");
        return;
    }

    deltaCrypto = clock() - beginCrypto;
    int inMilliCrypto = deltaCrypto * 1000 / CLOCKS_PER_SEC;
    totalCrypto = inMilliCrypto;

    for (int k = 0; k < NUM_ROUNDS; k++) {
        for (int j = 0; j < 4; j++) {
            localViews[k][j].x = shares[k][j];
        }
    }

    // Generate randomness for each round
    clock_t beginRandom = clock(), deltaRandom;
    unsigned char *randomness[NUM_ROUNDS][3];

    for (int k = 0; k < NUM_ROUNDS; k++) {
        for (int j = 0; j < 3; j++) {
            randomness[k][j] = malloc(1472 * sizeof(unsigned char));
            getAllRandomness(keys[k][j], randomness[k][j]);
        }
    }

    deltaRandom = clock() - beginRandom;
    int inMilliRandom = deltaRandom * 1000 / CLOCKS_PER_SEC;
    totalCrypto += inMilliRandom;

    // Run MPC-rand for each round
    clock_t beginSha = clock(), deltaSha;

    for (int k = 0; k < NUM_ROUNDS; k++) {
        as[k] = commit(shares[k], randomness[k], rs[k], localViews[k]);
        for (int j = 0; j < 3; j++) {
            free(randomness[k][j]);
        }
    }

    deltaSha = clock() - beginSha;
    int inMilliSha = deltaSha * 1000 / CLOCKS_PER_SEC;
    totalCrypto += inMilliSha;

    // Generate commitment hashes
    clock_t beginHash = clock(), deltaHash;

    signal(SIGSEGV, signal_handler);
    for (int k = 0; k < NUM_ROUNDS; k++) {
        uint32_t hash1[SHA256_DIGEST_LENGTH];
        H(keys[k][0], localViews[k][0], rs[k][0], &hash1);
        memcpy(as[k].h[0], &hash1, 32);
        H(keys[k][1], localViews[k][1], rs[k][1], &hash1);
        memcpy(as[k].h[1], &hash1, 32);
        H(keys[k][2], localViews[k][2], rs[k][2], &hash1);
        memcpy(as[k].h[2], &hash1, 32);
        H(NULL, localViews[k][3], NULL, &hash1);
        memcpy(as[k].h[3], &hash1, 32);
    }

    deltaHash = clock() - beginHash;
    int inMilliHash = deltaHash * 1000 / CLOCKS_PER_SEC;
    totalCrypto += inMilliHash;

    deltaA = clock() - begin;
    int inMilliA = deltaA * 1000 / CLOCKS_PER_SEC;

    // Generate challenges
    clock_t beginE = clock(), deltaE;
    int es[NUM_ROUNDS];
    uint32_t finalRand = (as[0].yp[0] + as[0].yp[1] + as[0].yp[2] + as[0].yp[3]) % MODULUS_1;
    printf("finalRand: %u\n", finalRand);
    H3(finalRand, as, NUM_ROUNDS, es);

    deltaE = clock() - beginE;
    int inMilliE = deltaE * 1000 / CLOCKS_PER_SEC;

    // Pack proofs
    clock_t beginZ = clock(), deltaZ;
    z *zs = malloc(sizeof(z) * NUM_ROUNDS);

    for (int i = 0; i < NUM_ROUNDS; i++) {
        zs[i] = prove(es[i], keys[i], rs[i], localViews[i]);
    }

    deltaZ = clock() - beginZ;
    int inMilliZ = deltaZ * 1000 / CLOCKS_PER_SEC;

    // Write results to file
    clock_t beginWrite = clock();
    FILE *file;
    char outputFile[256];
    int fileIndex = 1;

    sprintf(outputFile, "out%d_%d.bin", fileIndex, NUM_ROUNDS);

    while ((file = fopen(outputFile, "rb")) != NULL) {
        fclose(file);
        fileIndex++;
        sprintf(outputFile, "out%d_%d.bin", fileIndex, NUM_ROUNDS);
    }

    file = fopen(outputFile, "wb");
    if (!file) {
        printf("Unable to open file: %s\n", outputFile);
        free(zs);
        return;
    }

    fwrite(as, sizeof(a), NUM_ROUNDS, file);
    fwrite(zs, sizeof(z), NUM_ROUNDS, file);
    fclose(file);

    printf("Proof output to file %s\n", outputFile);

    clock_t deltaWrite = clock() - beginWrite;
    free(zs);
    int inMilliWrite = deltaWrite * 1000 / CLOCKS_PER_SEC;

    delta = clock() - begin;
    int inMilliTotal = delta * 1000 / CLOCKS_PER_SEC;

    // Print timing information
    printf("Generating A: %ju\n", (uintmax_t)inMilliA);
    printf("Generating keys: %ju\n", (uintmax_t)totalCrypto);
    printf("Generating randomness: %ju\n", (uintmax_t)inMilliRandom);
    printf("Running MPC-SHA2: %ju\n", (uintmax_t)inMilliSha);
    printf("Committing: %ju\n", (uintmax_t)inMilliHash);
    printf("Generating E: %ju\n", (uintmax_t)inMilliE);
    printf("Packing Z: %ju\n", (uintmax_t)inMilliZ);
    printf("Writing file: %ju\n", (uintmax_t)inMilliWrite);
    printf("Total: %d\n", inMilliTotal);

    openmp_thread_cleanup();
    cleanup_EVP();
}

// Function to write data to a file
// Write the specified data to a binary file, including GMP numbers
void write_to_file(const char* outputFile, mpz_t g, mpz_t h, uint32_t shares[NUM_ROUNDS][4], uint32_t shares_t[NUM_ROUNDS][4]) {
    FILE *file;
    clock_t beginWrite = clock();

    file = fopen(outputFile, "wb");
    if (!file) {
        printf("Unable to open file: %s\n", outputFile);
        return;
    }

    // Write GMP numbers g and h
    size_t count_g = mpz_sizeinbase(g, 2);
    size_t count_h = mpz_sizeinbase(h, 2);

    fwrite(&count_g, sizeof(size_t), 1, file);
    fwrite(&count_h, sizeof(size_t), 1, file);

    void* g_bin = malloc((count_g + 7) / 8);
    void* h_bin = malloc((count_h + 7) / 8);

    mpz_export(g_bin, NULL, 1, 1, 1, 0, g);
    mpz_export(h_bin, NULL, 1, 1, 1, 0, h);

    fwrite(g_bin, 1, (count_g + 7) / 8, file);
    fwrite(h_bin, 1, (count_h + 7) / 8, file);

    free(g_bin);
    free(h_bin);

    // Write shares and shares_t arrays
    fwrite(shares, sizeof(uint32_t), NUM_ROUNDS * 4, file);
    fwrite(shares_t, sizeof(uint32_t), NUM_ROUNDS * 4, file);

    fclose(file);

    clock_t deltaWrite = clock() - beginWrite;
    int inMilliWrite = deltaWrite * 1000 / CLOCKS_PER_SEC;
    printf("Data written to file %s in %d ms\n", outputFile, inMilliWrite);
}

// Main function
int main(void) {
    // Initialize GMP variables
    mpz_t p, g, R, h, k, t, result, result1, final_result, R_add_k;
    mpz_inits(p, g, R, h, k, t, result, result1, R_add_k, final_result, NULL);

    // Set generators g and h
    mpz_set_ui(g, 5);
    mpz_set_ui(h, 7);
    // Set random number R
    mpz_set_ui(R, 267);
    // Set private key or random number k, t
    mpz_set_ui(k, 59);
    mpz_set_ui(t, 9568);
    // R_add_k = R + k
    mpz_add(R_add_k, R, k);
    // Set modulus
    mpz_set_ui(p, 2);
    mpz_pow_ui(p, p, 521);

    uint32_t uint_R_add_k = (uint32_t)mpz_get_ui(R_add_k);
    uint32_t uint_t = (uint32_t)mpz_get_ui(t);

    // Calculate g^(R + k) mod p
    mpz_powm_ui(result, g, uint_R_add_k, p);
    // Calculate h^t mod p
    mpz_powm_ui(result1, h, mpz_get_ui(t), p);
    // Calculate final result (g^(R+k) * h^t) mod p
    mpz_mul(final_result, result, result1);
    mpz_mod(final_result, final_result, p);

    // Print results
    gmp_printf("t = %Zd\n", t);
    gmp_printf("(R + k) = %Zd\n", R_add_k);
    gmp_printf("g^(R + k) = %Zd\n", result);
    gmp_printf("h^t = %Zd\n", result1);
    gmp_printf("g^x.h^t = %Zd\n", final_result);

    // Timing
    clock_t start_time, end_time;
    double cpu_time_used;
    start_time = clock();

    uint32_t shares[NUM_ROUNDS][4];
    uint32_t shares_x1[NUM_ROUNDS][4];
    uint32_t shares_x2[NUM_ROUNDS][4];
    uint32_t shares_x3[NUM_ROUNDS][4];
    uint32_t shares_t[NUM_ROUNDS][4];

    // Generate random shares
    if (RAND_bytes((unsigned char *)shares, NUM_ROUNDS * 4 * sizeof(uint32_t)) != 1) {
        printf("RAND_bytes failed crypto, aborting\n");
        return 0;
    }
    for (int k = 0; k < NUM_ROUNDS; k++) {
        for (int j = 0; j < 4; j++) {
            shares[k][j] = shares[k][j] % MODULUS_p;
        }
        for (int j = 0; j < 4; j++) {
            shares_x1[k][j] = Ra(shares[k][j]);
            shares_x2[k][j] = Ra(Ra(shares[k][j]));
            shares_x3[k][j] = Ra(Ra(Ra(shares[k][j])));
            shares_t[k][j] = Ra(Ra(Ra(Ra(shares[k][j]))));
        }
    }

    // Calculate third party's shares
    for(int k = 0; k < NUM_ROUNDS; k++) {
        shares[k][3] = ((uint_R_add_k - shares[k][0] - shares[k][1] - shares[k][2]) % MODULUS_p + MODULUS_p) % MODULUS_p;
        shares_x1[k][3] = ((shares[k][1] - shares_x1[k][0] - shares_x1[k][1] - shares_x1[k][2]) % MODULUS_p + MODULUS_p) % MODULUS_p;
        shares_x2[k][3] = ((shares[k][2] - shares_x2[k][0] - shares_x2[k][1] - shares_x2[k][2]) % MODULUS_p + MODULUS_p) % MODULUS_p;
        shares_x3[k][3] = ((shares[k][3] - shares_x3[k][0] - shares_x3[k][1] - shares_x3[k][2]) % MODULUS_p + MODULUS_p) % MODULUS_p;
        shares_t[k][3] = ((uint_t - shares_t[k][0] - shares_t[k][1] - shares_t[k][2]) % MODULUS_p + MODULUS_p) % MODULUS_p;
    }

    printf("unit_t: %u\n", (shares_t[0][0] + shares_t[0][1] + shares_t[0][2] + shares_t[0][3]) % MODULUS_p);
    print_shares(shares, "shares");
    print_shares(shares_x1, "shares_x1");
    print_shares(shares_x2, "shares_x2");
    print_shares(shares_x3, "shares_x3");
    print_shares(shares_t, "shares_t");

    // Execute ZKLR
    ZKLR(shares, uint_R_add_k);
    ZKLR(shares_x1, shares[0][1]);
    ZKLR(shares_x2, shares[0][2]);
    ZKLR(shares_x3, shares[0][3]);
    ZKLR(shares_t, uint_t);

    // Timing
    end_time = clock();
    cpu_time_used = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
    printf("Execution time: %f seconds\n", cpu_time_used);
    fflush(stdout);

    // Write data to file
    write_to_file("output_data.bin", g, h, shares, shares_t);

    // Clear GMP variables
    mpz_clears(g, R, t, k, result, R_add_k, NULL);
    return EXIT_SUCCESS;
}