#ifndef SHARED_ELGAMAL_H
#define SHARED_ELGAMAL_H

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
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
#define MULTIPLIER_1 16804
#define INCREMENT_1 12344 //3086
#define MODULUS_1 10007   // 2^32
#define MODULUS_p 57      // 57  82 112

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
#define ySize 20

// View structure, using BIGNUM* type
typedef struct {
    BIGNUM *x;            // Input
    BIGNUM *y[ySize];    // Intermediate results
} View;

// a structure, using BIGNUM* type
typedef struct {
    BIGNUM *yp[4];            // Operation results
    unsigned char h[4][32];   
} a;

// z structure
typedef struct {
    unsigned char ke[16];     // Key
    unsigned char ke1[16];    // Key 1
    View ve;                  // First View structure
    View ve1;                 // Second View structure
    View ve3;                 // Public fourth path
    unsigned char re[4];      // Random number
    unsigned char re1[4];     // Random number 1
} z;

// Right rotate a 32-bit integer
#define RIGHTROTATE(x,n) (((x) >> (n)) | ((x) << (32-(n))))
// Left rotate a 32-bit integer
#define LEFTROTATE(x,n) (((x) << (n)) | ((x) >> (32-(n))))
// Get the i-th bit of a 32-bit integer
#define GETBIT(x, i) (((x) >> (i)) & 0x01)
// Set the i-th bit of a 32-bit integer
#define SETBIT(x, i, b)   x= (b)&1 ? (x)|(1 << (i)) : (x)&(~(1 << (i)))

// Initialize the View array
int initialize_views(View views[4]) {
    for (int i = 0; i < 4; i++) {
        // Initialize x
        views[i].x = BN_new();
        if (views[i].x == NULL) {
            fprintf(stderr, "Failed to allocate BIGNUM for views[%d].x.\n", i);
            // Free allocated resources
            for (int m = 0; m < i; m++) {
                BN_free(views[m].x);
                for (int n = 0; n < ySize; n++) {
                    BN_free(views[m].y[n]);
                }
            }
            return 1;
        }

        // Initialize y array
        for (int j = 0; j < ySize; j++) {
            views[i].y[j] = BN_new();
            if (views[i].y[j] == NULL) {
                fprintf(stderr, "Failed to allocate BIGNUM for views[%d].y[%d].\n", i, j);
                // Free allocated resources
                BN_free(views[i].x);
                for (int k = 0; k < j; k++) {
                    BN_free(views[i].y[k]);
                }
                for (int m = 0; m < i; m++) {
                    BN_free(views[m].x);
                    for (int n = 0; n < ySize; n++) {
                        BN_free(views[m].y[n]);
                    }
                }
                return 1;
            }
        }
    }
    return 0; // Success
}

// Free the View array
void free_views(View views[4]) {
    for (int i = 0; i < 4; i++) {
        BN_free(views[i].x);
        for (int j = 0; j < ySize; j++) {
            BN_free(views[i].y[j]);
        }
    }
}

// Handle OpenSSL errors
void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

// Generate randomness using AES encryption
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

// Get a 32-bit random number from the randomness array
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

// Calculate P = sum(g_i^y_i) + h^r, considering only non-zero y_i elements
// All operations are performed modulo p of the secp128r1 curve
void H(View v, EC_GROUP *group, EC_POINT *P_out) {
    BN_CTX *ctx = NULL;
    EC_POINT *g_i = NULL;
    EC_POINT *temp = NULL;
    EC_POINT *h = NULL;
    EC_POINT *temp_rh = NULL;
    BIGNUM *r = NULL;
    BIGNUM *rand_scalar = NULL;
    
    // Create a BN_CTX
    ctx = BN_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "H: Failed to create BN_CTX.\n");
        return;
    }

    // Initialize P_out
    if (P_out == NULL) {
        fprintf(stderr, "Failed to create EC_POINT.\n");
        goto cleanup;
    }

    // Get the generator G of the curve
    const EC_POINT *G = EC_GROUP_get0_generator(group);
    if (G == NULL) {
        fprintf(stderr, "H: Failed to get generator G.\n");
        goto cleanup;
    }

    // Get the order p of the curve
    const BIGNUM *p = EC_GROUP_get0_order(group);
    if (p == NULL) {
        fprintf(stderr, "Failed to get curve order.\n");
        EC_GROUP_free(group);  // Free the group
        return;
    }

    // Print the modulus p
    char *p_str = BN_bn2dec(p);
    printf("Curve order (p): %s\n", p_str);
    OPENSSL_free(p_str);  // Free the string

    // Count the number of non-zero y_i in ySize
    int n = 0;
    for (int i = 0; i < ySize; i++) {
        if (!BN_is_zero(v.y[i])) {
            n++;
        }
    }

    // If there are no non-zero y_i, generate h^r and return
    if (n == 0) {
        // Generate a random scalar r
        r = BN_new();
        if (r == NULL) {
            fprintf(stderr, "H: Failed to create r.\n");
            goto cleanup;
        }
        if (BN_rand_range(r, p) != 1) {
            fprintf(stderr, "H: Failed to generate random scalar r.\n");
            goto cleanup;
        }

        // Generate a random group element h = r * G
        h = EC_POINT_new(group);
        if (h == NULL) {
            fprintf(stderr, "H: Failed to create h.\n");
            goto cleanup;
        }
        if (EC_POINT_mul(group, h, r, NULL, NULL, ctx) != 1) {
            fprintf(stderr, "H: Failed to compute h = r * G.\n");
            goto cleanup;
        }

        // Add h to P_out
        if (EC_POINT_add(group, P_out, P_out, h, ctx) != 1) {
            fprintf(stderr, "H: Failed to add h to P_out.\n");
            goto cleanup;
        }
        goto cleanup;
    }

    // Iterate through ySize
    for (int i = 0; i < ySize; i++) {
        if (BN_is_zero(v.y[i])) {
            continue;
        }

        // Generate a random scalar
        rand_scalar = BN_new();
        if (rand_scalar == NULL) {
            fprintf(stderr, "H: Failed to create rand_scalar.\n");
            goto cleanup;
        }
        if (BN_rand_range(rand_scalar, p) != 1) {
            fprintf(stderr, "H: Failed to generate random scalar for g_i.\n");
            BN_free(rand_scalar);
            goto cleanup;
        }

        // Calculate g_i = rand_scalar * G
        g_i = EC_POINT_new(group);
        if (g_i == NULL) {
            fprintf(stderr, "H: Failed to create g_i.\n");
            BN_free(rand_scalar);
            goto cleanup;
        }
        if (EC_POINT_mul(group, g_i, rand_scalar, NULL, NULL, ctx) != 1) {
            fprintf(stderr, "H: Failed to compute g_i = rand_scalar * G.\n");
            EC_POINT_free(g_i);
            BN_free(rand_scalar);
            goto cleanup;
        }

        // Calculate temp = y_i * g_i
        temp = EC_POINT_new(group);
        if (temp == NULL) {
            fprintf(stderr, "H: Failed to create temp.\n");
            EC_POINT_free(g_i);
            BN_free(rand_scalar);
            goto cleanup;
        }
        BIGNUM *mod_result = BN_new();
        if (mod_result == NULL) {
            fprintf(stderr, "H: Failed to create mod_result.\n");
            EC_POINT_free(temp);
            EC_POINT_free(g_i);
            BN_free(rand_scalar);
            goto cleanup;
        }
        if (v.y[i] == NULL || p == NULL) {
            fprintf(stderr, "Invalid BIGNUM at v.y[%d] or curve order p.\n", i);
            goto cleanup;
        }
        // Perform modulo p operation on v.y[i]
        if (BN_mod(mod_result, v.y[i], p, ctx) != 1) {
            fprintf(stderr, "H: Failed to compute v.y[%d] mod p.\n", i);
            BN_free(mod_result);
            EC_POINT_free(temp);
            EC_POINT_free(g_i);
            BN_free(rand_scalar);
            goto cleanup;
        }
        // Replace the original value of v.y[i] with the result of the modulo operation
        BN_copy(v.y[i], mod_result);
        BN_free(mod_result);

        if (EC_POINT_mul(group, temp, NULL, g_i, v.y[i], ctx) != 1) {
            fprintf(stderr, "H: Failed to compute temp = y[%d] * g_i.\n", i);
            EC_POINT_free(temp);
            EC_POINT_free(g_i);
            BN_free(rand_scalar);
            goto cleanup;
        }

        // Add temp to P_out
        if (EC_POINT_add(group, P_out, P_out, temp, ctx) != 1) {
            fprintf(stderr, "H: Failed to add temp to P_out.\n");
            EC_POINT_free(temp);
            EC_POINT_free(g_i);
            BN_free(rand_scalar);
            goto cleanup;
        }

        // Free temporary objects
        EC_POINT_free(temp);
        EC_POINT_free(g_i);
        BN_free(rand_scalar);
    }

    // Generate a random scalar r
    r = BN_new();
    if (r == NULL) {
        fprintf(stderr, "H: Failed to create r.\n");
        goto cleanup;
    }
    if (BN_rand_range(r, p) != 1) {
        fprintf(stderr, "H: Failed to generate random scalar r.\n");
        goto cleanup;
    }

    // Generate a random group element h = r * G
    h = EC_POINT_new(group);
    if (h == NULL) {
        fprintf(stderr, "H: Failed to create h.\n");
        goto cleanup;
    }
    if (EC_POINT_mul(group, h, r, NULL, NULL, ctx) != 1) {
        fprintf(stderr, "H: Failed to compute h = r * G.\n");
        goto cleanup;
    }

    // Add h to P_out
    if (EC_POINT_add(group, P_out, P_out, h, ctx) != 1) {
        fprintf(stderr, "H: Failed to add h to P_out.\n");
        goto cleanup;
    }

cleanup:
    if (r) BN_free(r);
    if (h) EC_POINT_free(h);
    if (ctx) BN_CTX_free(ctx);
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
        printf("AND false: %d %d\n", ve.y[*countY], t);
        return 1;
    }
    z[0] = t;
    z[1] = ve1.y[*countY];
    z[2] = ve3.y[*countY];
    z[3] = ve4.y[*countY];
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

// ...（继续之前的代码）

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
    int *countY = calloc(1, sizeof(int));
    if (!countY) return 1;

    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime192v1);
    if (!group) {
        free(countY);
        return 1;
    }

    // Verify first hash
    EC_POINT *P1 = EC_POINT_new(group);
    H(z.ve, group, P1);
    unsigned char hash1[SHA256_DIGEST_LENGTH];
    EC_POINT_point2oct(group, P1, POINT_CONVERSION_UNCOMPRESSED, hash1, sizeof(hash1), NULL);
    if (memcmp(hash1, a.h[e], SHA256_DIGEST_LENGTH) != 0) {
        EC_POINT_free(P1);
        EC_GROUP_free(group);
        free(countY);
        return 1;
    }

    // Verify second hash
    EC_POINT *P2 = EC_POINT_new(group);
    H(z.ve1, group, P2);
    unsigned char hash2[SHA256_DIGEST_LENGTH];
    EC_POINT_point2oct(group, P2, POINT_CONVERSION_UNCOMPRESSED, hash2, sizeof(hash2), NULL);
    if (memcmp(hash2, a.h[(e+1)%3], SHA256_DIGEST_LENGTH) != 0) {
        EC_POINT_free(P2);
        EC_GROUP_free(group);
        free(countY);
        return 1;
    }

    // Verify third hash
    EC_POINT *P3 = EC_POINT_new(group);
    H(z.ve3, group, P3);
    unsigned char hash3[SHA256_DIGEST_LENGTH];
    EC_POINT_point2oct(group, P3, POINT_CONVERSION_UNCOMPRESSED, hash3, sizeof(hash3), NULL);
    if (memcmp(hash3, a.h[3], SHA256_DIGEST_LENGTH) != 0) {
        EC_POINT_free(P3);
        EC_GROUP_free(group);
        free(countY);
        return 1;
    }

    // Verify randomness
    BIGNUM *results[4] = {BN_new(), BN_new(), BN_new(), BN_new()};
    BIGNUM *new_seed[4] = {BN_dup(z.ve.x), BN_dup(z.ve1.x), BN_dup(z.ve3.x), BN_dup(z.ve3.x)};
    
    if (!results[0] || !results[1] || !results[2] || !results[3] ||
        !new_seed[0] || !new_seed[1] || !new_seed[2] || !new_seed[3]) {
        // Cleanup code
        free(countY);
        return 1;
    }

    unsigned char *randomness[3] = {z.re, z.re1, z.re};
    View views[4] = {z.ve, z.ve1, z.ve3, z.ve3};
    
    if (mpc_rand(results, new_seed, EC_GROUP_get0_order(group), randomness, views, countY) != 0) {
        // Cleanup code
        free(countY);
        return 1;
    }

    // Verify results
    for (int i = 0; i < 4; i++) {
        if (BN_cmp(results[i], a.yp[e]) != 0) {
            // Cleanup code
            free(countY);
            return 1;
        }
    }

    // Cleanup
    EC_POINT_free(P1);
    EC_POINT_free(P2);
    EC_POINT_free(P3);
    EC_GROUP_free(group);
    free(countY);
    return 0;
}

#endif /* SHARED_ELGAMAL_H_ */