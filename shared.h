#ifndef SHARED_H_
#define SHARED_H_

#include <openssl/sha.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <openssl/obj_mac.h>
#ifdef _WIN32
#include <openssl/applink.c>
#endif
#include <openssl/rand.h>
#include "omp.h"

// Number of rounds
const int NUM_ROUNDS = 1;
// Verbose mode flag
#define VERBOSE TRUE

// LCG parameters 1
#define MULTIPLIER_1 16807
#define INCREMENT_1 12344 //3086
#define MODULUS_1 10007   // 2^32
#define MODULUS_p 1511   //    57  82 112

// Initial hash values for SHA-256
static const uint32_t hA[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476,
                                0xC3D2E1F0};

// Round constants for SHA-256
static const uint32_t k[64] = { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
                                0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
                                0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
                                0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6,
                                0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                                0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3,
                                0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138,
                                0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e,
                                0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
                                0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
                                0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
                                0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814,
                                0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

// Size of y array in View structure
#define ySize 9

// View structure, storing input and intermediate results
typedef struct {
    uint32_t x;         // Input
    uint32_t y[ySize];  // Intermediate results
} View;

// Structure a, storing operation results and SHA-256 hashed results
typedef struct {
    uint32_t yp[4];             // Operation results
    unsigned char h[4][32];     // Results after SHA-256 encryption
} a;

// Verification structure - 3 paths for 2 to 1 deduction
typedef struct {
    // Three keys
    unsigned char ke[16];
    unsigned char ke1[16];

    // Five View structures
    // Two random paths among the first three paths
    View ve;
    View ve1;

    View ve3;       // The public fourth path

    // Three random numbers
    unsigned char re[4];
    unsigned char re1[4];
} z;

// Right rotate a 32-bit integer
#define RIGHTROTATE(x,n) (((x) >> (n)) | ((x) << (32-(n))))
// Left rotate a 32-bit integer
#define LEFTROTATE(x,n) (((x) << (n)) | ((x) >> (32-(n))))
// Get the i-th bit of a 32-bit integer
#define GETBIT(x, i) (((x) >> (i)) & 0x01)
// Set the i-th bit of a 32-bit integer
#define SETBIT(x, i, b)   x= (b)&1 ? (x)|(1 << (i)) : (x)&(~(1 << (i)))

// Handle OpenSSL errors
void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}


// template <typename T>
// typename std::enable_if<std::is_integral<T>::value, T>::type
// mod(T a, T m) {
//     if (m == 0) {
//         throw std::invalid_argument("Modulus cannot be zero.");
//     }
//     if constexpr (std::is_unsigned<T>::value) {
//         return a % m;
//     } else {
//         T result = a % m;
//         if (result < 0) {
//             result += m;
//         }
//         return result;
//     }
// }

// template <typename T>
// typename std::enable_if<std::is_floating_point<T>::value, T>::type
// mod(T a, T m) {
//     if (m == 0) {
//         throw std::invalid_argument("Modulus cannot be zero.");
//     }
//     T result = std::fmod(a, m);
//     if (result < 0) {
//         result += m;
//     }
//     return result;
// }

// Generate random numbers. Use different keys if you need different random numbers each time.
void getAllRandomness(unsigned char key[16], unsigned char randomness[1472]) {
    // Generate randomness: We use 365*32 bit of randomness per key.
    // Since AES block size is 128 bit, we need to run 365*32/128 = 91.25 iterations. Let's just round up.
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    unsigned char *iv = (unsigned char *)"0123456789012345";
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv);
    unsigned char *plaintext = (unsigned char *)"0000000000000000";
    int len;
    for(int j = 0; j < 92; j++) {
        EVP_EncryptUpdate(ctx, &randomness[j*16], &len, plaintext, strlen((char *)plaintext));
    }
    EVP_CIPHER_CTX_free(ctx);
}

// Copy four bytes of data from the randCount position of randomness to the buffer, and increment randCount by 4 after use.
uint32_t getRandom32(uint32_t randomness[1472], int randCount) {
    uint32_t ret;
    memcpy(&ret, &randomness[randCount], 4);
    return ret;
}

// Initialize the OpenSSL EVP library
void init_EVP() {
    /* Initialize the library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
}

// Clean up the OpenSSL EVP library
void cleanup_EVP() {
    /* Clean up */
    EVP_cleanup();
    ERR_free_strings();
}

// Perform SHA-256 encryption. Combine multiple inputs (including a key, a View structure, and a random number)
// to generate a 256-bit (32-byte) hash value and store it in hash.
void H(unsigned char k[16], View v, unsigned char r[4], unsigned char hash[SHA256_DIGEST_LENGTH]) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    // If the key is not NULL, include it in the hash calculation
    if (k != NULL) {
        SHA256_Update(&ctx, k, 16);
    }

    // Include the View in the hash calculation
    SHA256_Update(&ctx, &v, sizeof(v));

    // If the random number is not NULL, include it in the hash calculation
    if (r != NULL) {
        SHA256_Update(&ctx, r, 4);
    }

    SHA256_Final(hash, &ctx);
}

// Generate challenges based on SHA-256 hash
void H3(uint32_t y, a* as, int s, int* es) {
    unsigned char hash[SHA256_DIGEST_LENGTH]; // SHA-256 digest length is 32 bytes
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, &y, sizeof(y));
    SHA256_Update(&ctx, as, sizeof(a)*s);
    SHA256_Final(hash, &ctx);

    // Pick bits from the hash
    int i = 0;
    int bitTracker = 0; // Challenge bit tracker
    // Round loop
    while (i < s) {
        // If the challenge bit count exceeds 256, generate a new hash
        if (bitTracker >= SHA256_DIGEST_LENGTH * 8) { 
            SHA256_Init(&ctx);
            SHA256_Update(&ctx, hash, sizeof(hash));
            SHA256_Final(hash, &ctx);
            bitTracker = 0;
            //printf("Generated new hash\n");
        }
        // b1 and b2 are two consecutive bits extracted from the hash
        int b1 = GETBIT(hash[bitTracker / 8], bitTracker % 8);
        int b2 = GETBIT(hash[(bitTracker + 1) / 8], (bitTracker + 1) % 8);
        if (b1 == 0) {
            if (b2 == 0) {
                es[i] = 0;
                bitTracker += 2;
                i++;
            } else {
                es[i] = 1;
                bitTracker += 2;
                i++;
            }
        } else {
            if (b2 == 0) {
                es[i] = 2;
                bitTracker += 2;
                i++;
            } else {
                bitTracker += 2;
            }
        }
    }
}

// Copy the last 20 bytes of v.y to the result
void output(View v, uint32_t* result) {
    memcpy(result, &v.y[ySize - 5], 20);
}

// Reconstruct the result by summing four values and taking the modulo
void reconstruct(uint32_t y0, uint32_t y1, uint32_t y2, uint32_t y3, uint32_t *result) {
    *result = (y0 + y1 + y2 + y3) % MODULUS_1;
}

// Perform XOR operation on two arrays of 32-bit integers
void mpc_XOR2(uint32_t x[4], uint32_t y[4], uint32_t z[4]) {
    z[0] = x[0] ^ y[0];
    z[1] = x[1] ^ y[1];
    z[2] = x[2] ^ y[2];
    z[3] = x[3] ^ y[3];
}

// Perform bitwise negation operation on an array of 32-bit integers
void mpc_NEGATE2(uint32_t x[4], uint32_t z[4]) {
    z[0] = ~x[0];
    z[1] = ~x[1];
    z[2] = ~x[2];
    z[3] = ~x[3];
}

// OpenMP locks
omp_lock_t *locks;

// OpenMP locking callback
void openmp_locking_callback(int mode, int type, char *file, int line)
{
    if (mode & CRYPTO_LOCK)
    {
        omp_set_lock(&locks[type]);
    }
    else
    {
        omp_unset_lock(&locks[type]);
    }
}

// OpenMP thread ID callback
unsigned long openmp_thread_id(void)
{
    return (unsigned long)omp_get_thread_num();
}

// Set up OpenMP threads for OpenSSL
void openmp_thread_setup(void)
{
    int i;

    locks = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(omp_lock_t));
    for (i = 0; i < CRYPTO_num_locks(); i++)
    {
        omp_init_lock(&locks[i]);
    }

    CRYPTO_set_id_callback((unsigned long (*)())openmp_thread_id);
    CRYPTO_set_locking_callback((void (*)())openmp_locking_callback);
}

// Clean up OpenMP threads for OpenSSL
void openmp_thread_cleanup(void)
{
    int i;

    CRYPTO_set_id_callback(NULL);
    CRYPTO_set_locking_callback(NULL);
    for (i = 0; i < CRYPTO_num_locks(); i++)
        omp_destroy_lock(&locks[i]);
    OPENSSL_free(locks);
}

// Verify the AND operation in MPC
int mpc_AND_verify(uint32_t x[4], uint32_t y[4], uint32_t z[4], View ve, View ve1, View ve3, View ve4, uint32_t *randomness[2], int* randCount, int* countY) {
    uint32_t r[2] = { getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount)};
    *randCount += 4;

    uint32_t t = 0;
    t = (x[0] & y[1]) ^ (x[1] & y[0]) ^ (x[2] & y[3]) ^ (x[0] & y[2]) ^ (x[0] & y[0]) ^ r[0] ^ r[1];

    if (ve.y[*countY] != t) {
        printf("AND verification failed: %d %d\n", ve.y[*countY], t);
        return 1;
    }
    z[0] = t;
    z[1] = ve1.y[*countY];
    z[2] = ve3.y[*countY];
    z[3] = ve4.y[*countY];
    (*countY)++;
    return 0;
}

// Verify the ADD operation in MPC
int mpc_ADD_verify(uint32_t x[4], uint32_t y[4], uint32_t z[4], View ve, View ve1, View ve3, View ve4, uint32_t *randomness[2], int* randCount, int* countY) {
    uint32_t r[2] = { getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount)};
    *randCount += 4;

    uint8_t a[4], b[4];
    uint8_t t;

    for(int i = 0; i < 31; i++)
    {
        a[0] = GETBIT(x[0] ^ ve.y[*countY], i);
        a[1] = GETBIT(x[1] ^ ve1.y[*countY], i);
        a[2] = GETBIT(x[2] ^ ve3.y[*countY], i);
        a[3] = GETBIT(x[3] ^ ve4.y[*countY], i);

        b[0] = GETBIT(y[0] ^ ve.y[*countY], i);
        b[1] = GETBIT(y[1] ^ ve1.y[*countY], i);
        b[2] = GETBIT(y[2] ^ ve3.y[*countY], i);
        b[3] = GETBIT(y[3] ^ ve4.y[*countY], i);

        t = (a[0] & b[1]) ^ (a[1] & b[0]) ^ (a[1] & b[3]) ^ (a[1] & b[2]) ^ GETBIT(r[0], i);
        if (GETBIT(ve.y[*countY], i + 1) != (t ^ (a[0] & b[0]) ^ GETBIT(ve.y[*countY], i) ^ GETBIT(r[1], i))) {
            printf("ADD verification failed: %d %d\n", ve.y[*countY], t);
            return 1;
        }
    }

    z[0] = x[0] ^ y[0] ^ ve.y[*countY];
    z[1] = x[1] ^ y[1] ^ ve1.y[*countY];
    z[2] = x[2] ^ y[2] ^ ve3.y[*countY];
    z[3] = x[3] ^ y[3] ^ ve4.y[*countY];
    (*countY)++;
    return 0;
}

// Perform right rotation on an array of 32-bit integers
void mpc_RIGHTROTATE2(uint32_t x[], int i, uint32_t z[]) {
    z[0] = RIGHTROTATE(x[0], i);
    z[1] = RIGHTROTATE(x[1], i);
    z[2] = RIGHTROTATE(x[2], i);
    z[3] = RIGHTROTATE(x[3], i);
}

// Perform right shift operation on an array of 32-bit integers
void mpc_RIGHTSHIFT2(uint32_t x[4], int i, uint32_t z[4]) {
    z[0] = x[0] >> i;
    z[1] = x[1] >> i;
    z[2] = x[2] >> i;
    z[3] = x[3] >> i;
}

// Verify the scalar multiplication operation in MPC
void mpc_MULK_verify(uint32_t x[4], uint32_t y, uint32_t z[4], View views[4], int* countY) {
    // Perform scalar multiplication directly, multiplying each x[i] by the scalar y
    for (int i = 0; i < 4; i++) {
        z[i] = x[i] * y;  // Perform scalar multiplication
        views[i].y[*countY] = z[i];   // Save the multiplication result to the view
    }
    *countY += 1;
}

// Verify the MAJ operation in MPC
int mpc_MAJ_verify(uint32_t a[4], uint32_t b[4], uint32_t c[4], uint32_t z[4], View ve, View ve1, View ve3, View ve4, uint32_t *randomness[2], int* randCount, int* countY) {
    uint32_t t0[5];
    uint32_t t1[5];

    mpc_XOR2(a, b, t0);
    mpc_XOR2(a, c, t1);

    if (mpc_AND_verify(t0, t1, z, ve, ve1, ve3, ve4, randomness, randCount, countY) == 1) {
        printf("MAJ verification failed\n");
        return 1;
    }

    mpc_XOR2(z, a, z);
    return 0;
}

// Verify the CH operation in MPC
int mpc_CH_verify(uint32_t e[4], uint32_t f[4], uint32_t g[4], uint32_t z[4], View ve, View ve1, View ve3, View ve4, uint32_t *randomness[2], int* randCount, int* countY) {
    uint32_t t0[5];
    mpc_XOR2(f, g, t0);

    if (mpc_AND_verify(e, t0, t0, ve, ve1, ve3, ve4, randomness, randCount, countY) == 1) {
        printf("CH verification failed\n");
        return 1;
    }

    mpc_XOR2(t0, g, z);
    return 0;
}

// Verify the MPC random number generation
int mpc_rand_verify(a a, int e, z z) {
    unsigned char* hash = malloc(SHA256_DIGEST_LENGTH);
    int* countY = calloc(1, sizeof(int));

    // Verify the first part of the challenger's key, view, and random number
    H(z.ke, z.ve, z.re, hash);
    if (memcmp(a.h[e], hash, 32) != 0) {
        printf("Verification failed at hash %d\n", e);
        free(hash);
        return 1;
    }

    // Verify the second part of the challenger's key, view, and random number
    H(z.ke1, z.ve1, z.re1, hash);
    if (memcmp(a.h[(e + 1) % 3], hash, 32) != 0) {
        printf("Verification failed at hash %d\n", (e + 1) % 3);
        free(hash);
        return 1;
    }

    free(hash);

    // Recalculate the result of mpc_rand and compare it with the result in `a.yp`
    uint32_t results[4];
    uint32_t temp_results[4];
    uint32_t seed[4];

    // Get the seed values from the view
    for (int i = 0; i < 4; i++) {
        seed[i] = z.ve.x;  // Assume the seed is stored in ve.x
    }

    // Reperform scalar multiplication
    uint32_t temp[4];
    mpc_MULK_verify(seed, MULTIPLIER_1, temp, &z.ve, countY);

    // Recalculate the results
    for (int i = 0; i < 4; i++) {
        temp_results[i] = temp[i] + (INCREMENT_1 / 4);
    }

    // Verify if the output of each view matches the provided result
    for (int i = 0; i < 4; i++) {
        if (memcmp(&a.yp[e], &temp_results[i], sizeof(uint32_t)) != 0) {
            printf("Verification failed at result %d\n", i);
            return 1;
        }
    }

    return 0;  // Verification successful
}

#endif /* SHARED_H_ */