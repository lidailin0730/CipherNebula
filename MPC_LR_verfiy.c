#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <gmp.h>
#include "shared.h"

// Print the binary representation of a 32-bit unsigned integer
void printbits(uint32_t n) {
    if (n) {
        printbits(n >> 1);
        printf("%d", n & 1);
    }
}

// Read the proof objects 'as' and 'zs' from the proof file into 'a' and 'z'
/*
a {
    uint32_t yp[4][8]; // Store the hash values after SHA operation of three participants, array capacity is 8 * 32 bits
    unsigned char h[4][32]; // Store the hash values of three parties, array capacity is 32 bytes
}

z {
    // Three keys
    unsigned char ke[16];
    unsigned char ke1[16];
    unsigned char ke2[16];
    // Five View structures
    View ve;
    View ve1;
    View ve2;
    View ve3;
    // Three random numbers
    unsigned char re[4];
    unsigned char re1[4];
    unsigned char re2[4];
} z;
*/

// Read data from a file including GMP numbers and share arrays
void read_from_file(const char* inputFile, mpz_t g, mpz_t h, uint32_t shares[NUM_ROUNDS][4], uint32_t shares_t[NUM_ROUNDS][4]) {
    FILE *file;
    // Open the file for reading in binary mode
    file = fopen(inputFile, "rb");
    if (!file) {
        printf("Unable to open file: %s\n", inputFile);
        return;
    }

    // Read the sizes of g and h
    size_t count_g, count_h;
    fread(&count_g, sizeof(size_t), 1, file);  // Read the size of g
    fread(&count_h, sizeof(size_t), 1, file);  // Read the size of h

    void* g_bin = malloc((count_g + 7) / 8);
    void* h_bin = malloc((count_h + 7) / 8);

    fread(g_bin, 1, (count_g + 7) / 8, file);  // Read the binary data of g
    fread(h_bin, 1, (count_h + 7) / 8, file);  // Read the binary data of h

    mpz_import(g, (count_g + 7) / 8, 1, 1, 1, 0, g_bin);  // Import g
    mpz_import(h, (count_h + 7) / 8, 1, 1, 1, 0, h_bin);  // Import h

    free(g_bin);
    free(h_bin);

    // Read the shares and shares_t arrays
    fread(shares, sizeof(uint32_t), NUM_ROUNDS * 4, file);
    fread(shares_t, sizeof(uint32_t), NUM_ROUNDS * 4, file);

    // Close the file
    fclose(file);
}

// Read data from a file and convert it to mpz_t type
int read_com_file(const char *file_name) {
    mpz_t results[NUM_ROUNDS][4];
    // Open the file for reading in binary mode
    FILE *file_com = fopen(file_name, "rb");
    if (!file_com) {
        perror("Failed to open file");
        return 1;
    }

    // Read data from the file and convert it to mpz_t type
    for (int i = 0; i < NUM_ROUNDS; i++) {
        for (int j = 0; j < 4; j++) {  // Bug fix: Changed INT_MAX to 4
            // Initialize mpz_t variable
            mpz_init(results[i][j]);

            // Assume each mpz_t number is stored in 4 bytes
            size_t count = 4;
            unsigned char bytes[count];

            // Read byte data
            size_t bytesRead = fread(bytes, 1, count, file_com);
            if (bytesRead != count) {
                fprintf(stderr, "Failed to read data or reached the end of the file prematurely\n");
                fclose(file_com);
                return 1;
            }

            // Use mpz_import to import byte data into mpz_t type
            mpz_import(results[i][j], count, 1, 1, 0, 0, bytes);

            // Optional: Print the decimal representation of each mpz_t number
            // gmp_printf("results[%d][%d] = %Zd\n", i, j, results[i][j]);
        }
    }

    // Close the file
    fclose(file_com);
    return 0;
}

// Print an EC_POINT as a BIGNUM in decimal representation
void print_point_as_bn(const EC_GROUP *group, EC_POINT *point) {
    BIGNUM *bn = BN_new();
    BN_CTX *ctx = BN_CTX_new();  // Create a BN_CTX context
    if (bn == NULL || ctx == NULL) {
        fprintf(stderr, "Failed to create BIGNUM or BN_CTX.\n");
        return;
    }

    // Convert EC_POINT to BIGNUM
    EC_POINT_point2bn(group, point, POINT_CONVERSION_UNCOMPRESSED, bn, ctx);

    // Print the decimal representation of BIGNUM
    char *bn_str = BN_bn2dec(bn);
    if (bn_str != NULL) {
        printf("Point as BIGNUM: %s\n", bn_str);
        OPENSSL_free(bn_str);
    } else {
        fprintf(stderr, "Failed to convert BIGNUM to string.\n");
    }

    BN_free(bn);
    BN_CTX_free(ctx);  // Free the BN_CTX
}

// Perform the MPC random number generation operation
int mpc_rand(BIGNUM *results[4], BIGNUM *new_seed[4], const BIGNUM *p) {
    int ret = 1; // Default to return an error
    BN_CTX *ctx = NULL;
    BIGNUM *seed[4] = {NULL, NULL, NULL, NULL};
    BIGNUM *temp_mulk[4] = {NULL, NULL, NULL, NULL};
    BIGNUM *increment = NULL;

    // Create a BN_CTX
    ctx = BN_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "mpc_rand: Failed to create BN_CTX.\n");
        goto cleanup;
    }

    // Initialize the seeds: seed[i] = new_seed[i]
    for (int i = 0; i < 4; i++) {
        seed[i] = BN_dup(new_seed[i]);
        if (seed[i] == NULL) {
            fprintf(stderr, "mpc_rand: Failed to duplicate new_seed[%d].\n", i);
            goto cleanup;
        }

        // Print the initialized seed[i] value
        char *seed_str = BN_bn2dec(seed[i]);
        printf("Seed[%d]: %s\n", i, seed_str);
        OPENSSL_free(seed_str);
    }

    // Initialize the temp_mulk array
    for (int i = 0; i < 4; i++) {
        temp_mulk[i] = BN_new();
        if (temp_mulk[i] == NULL) {
            fprintf(stderr, "mpc_rand: Failed to create temp_mulk[%d].\n", i);
            goto cleanup;
        }
    }

    // Perform the mpc_MULK operation: temp_mulk = (MULTIPLIER_1 * seed) mod p
    for (int i = 0; i < 4; i++) {
        if (BN_mul(temp_mulk[i], seed[i], BN_value_one(), ctx) != 1) {  // MULTIPLIER_1 * seed
            fprintf(stderr, "mpc_rand: Failed to multiply seed[%d] by MULTIPLIER_1.\n", i);
            goto cleanup;
        }
        if (BN_mod(temp_mulk[i], temp_mulk[i], p, ctx) != 1) {  // temp_mulk[i] = temp_mulk[i] mod p
            fprintf(stderr, "mpc_rand: Failed to mod temp_mulk[%d] by p.\n", i);
            goto cleanup;
        }

        // Print the value of temp_mulk
        char *temp_str = BN_bn2dec(temp_mulk[i]);
        printf("Temp_mulk[%d]: %s\n", i, temp_str);
        OPENSSL_free(temp_str);
    }

    // Print the value of temp_mulk
    for (int i = 0; i < 4; i++) {
        char *temp_str = BN_bn2dec(temp_mulk[i]);
        printf("Temp_mulk[%d]: %s\n", i, temp_str);
        OPENSSL_free(temp_str);
    }

    // Create and set increment = INCREMENT_1 / 4
    increment = BN_new();
    if (increment == NULL) {
        fprintf(stderr, "mpc_rand: Failed to create BIGNUM for increment.\n");
        goto cleanup;
    }

    if (!BN_set_word(increment, INCREMENT_1 / 4)) {
        fprintf(stderr, "mpc_rand: Failed to set increment.\n");
        goto cleanup;
    }

    // Print the value of increment
    char *increment_str = BN_bn2dec(increment);
    printf("Increment: %s\n", increment_str);
    OPENSSL_free(increment_str);

    // Perform results[i] = (temp_mulk[i] + increment) mod p
    for (int i = 0; i < 4; i++) {
        if (BN_mod_add(results[i], temp_mulk[i], increment, p, ctx) != 1) {
            fprintf(stderr, "mpc_rand: Failed to compute (temp_mulk[%d] + increment) mod p.\n", i);
            goto cleanup;
        }

        // Print the result results[i] value
        char *result_str = BN_bn2dec(results[i]);
        printf("Results[%d]: %s\n", i, result_str);
        OPENSSL_free(result_str);
    }

    // Success
    ret = 0;

cleanup:
    // Free resources
    if (seed[0]) BN_free(seed[0]);
    if (seed[1]) BN_free(seed[1]);
    if (seed[2]) BN_free(seed[2]);
    if (seed[3]) BN_free(seed[3]);

    if (temp_mulk[0]) BN_free(temp_mulk[0]);
    if (temp_mulk[1]) BN_free(temp_mulk[1]);
    if (temp_mulk[2]) BN_free(temp_mulk[2]);
    if (temp_mulk[3]) BN_free(temp_mulk[3]);

    if (increment) BN_free(increment);
    if (ctx) BN_CTX_free(ctx);

    return ret;
}

// Main function of the program
int main(int argc, char *argv[]) {
    // Start timing
    clock_t start_time, end_time;
    double cpu_time_used;
    start_time = clock();

    // Initialize the OpenSSL library and OpenMP thread settings
    setbuf(stdout, NULL);
    init_EVP();
    openmp_thread_setup();
    printf("Iterations of SHA: %d\n", NUM_ROUNDS);
    clock_t begin = clock(), delta, deltaFiles;
    // secp128r1 NID_X9_62_prime192v1
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp128r1);
    if (group == NULL) {
        fprintf(stderr, "Failed to load curve parameters.\n");
        return 1;
    }

    // Get the order p of the curve
    const BIGNUM *p = EC_GROUP_get0_order(group);
    if (p == NULL) {
        fprintf(stderr, "Failed to get curve order.\n");
        EC_GROUP_free(group);
        return 1;
    }

    // Print the order p
    char *p_str = BN_bn2dec(p);
    printf("Curve order (p): %s\n", p_str);
    OPENSSL_free(p_str);

    // Get the base point g
    EC_POINT *g = EC_GROUP_get0_generator(group);
    if (g == NULL) {
        fprintf(stderr, "Failed to get curve generator.\n");
        EC_GROUP_free(group);
        return 1;
    }

    EC_POINT *temp_result = EC_POINT_new(group);
    if (temp_result == NULL) {
        fprintf(stderr, "Failed to create EC_POINT for result.\n");
        EC_GROUP_free(group);
        return 1;
    }
    BIGNUM *x1 = BN_new();
    BIGNUM *x2 = BN_new();
    BIGNUM *x3 = BN_new();
    BIGNUM *x4 = BN_new();
    BIGNUM *new_seed[4] = {x1, x2, x3, x4};

    // Define the results array to receive the random numbers generated by mpc_rand
    BIGNUM *results[4] = {BN_new(), BN_new(), BN_new(), BN_new()};

    if (x1 == NULL || x2 == NULL || x3 == NULL || x4 == NULL) {
        fprintf(stderr, "Failed to create BIGNUMs for random values.\n");
        EC_GROUP_free(group);
        return 1;
    }

    // Generate random numbers x1, x2, x3, x4
    if (BN_rand_range(x1, p) != 1 || BN_rand_range(x2, p) != 1 || BN_rand_range(x3, p) != 1 || BN_rand_range(x4, p) != 1) {
        fprintf(stderr, "Failed to generate random scalars.\n");
        BN_free(x1);
        BN_free(x2);
        BN_free(x3);
        BN_free(x4);
        EC_GROUP_free(group);
        return 1;
    }
    clock_t start_time1, end_time1;
    double time_taken;
    start_time1 = clock();  // Record the start time of the multiplication operation

    // Compute g^x1, g^x2, g^x3, g^x4
    EC_POINT *g_x1 = EC_POINT_new(group);
    for(int i = 0; i < 10; i++){
        EC_POINT_mul(group, g_x1, x1, NULL, NULL, NULL);
    }
    if (EC_POINT_mul(group, g_x1, x1, NULL, NULL, NULL) != 1) {
        fprintf(stderr, "Failed to compute g^x1.\n");
        EC_POINT_free(g_x1);
        BN_free(x1);
        BN_free(x2);
        BN_free(x3);
        BN_free(x4);
        EC_GROUP_free(group);
        return 1;
    }
    printf("g^x1:\n");
    print_point_as_bn(group, g_x1);

    end_time1 = clock();  // Record the end time of the addition operation
    time_taken = (double)(end_time1 - start_time1) / CLOCKS_PER_SEC;  // Calculate the time

    printf("Time taken for addition and modulo operation: %f seconds\n", time_taken);

    EC_POINT *g_x2 = EC_POINT_new(group);
    if (EC_POINT_mul(group, g_x2, x2, NULL, NULL, NULL) != 1) {
        fprintf(stderr, "Failed to compute g^x2.\n");
        EC_POINT_free(g_x1);
        EC_POINT_free(g_x2);
        BN_free(x1);
        BN_free(x2);
        BN_free(x3);
        BN_free(x4);
        EC_GROUP_free(group);
        return 1;
    }
    printf("g^x2:\n");
    print_point_as_bn(group, g_x2);

    EC_POINT *g_x3 = EC_POINT_new(group);
    if (EC_POINT_mul(group, g_x3, x3, NULL, NULL, NULL) != 1) {
        fprintf(stderr, "Failed to compute g^x3.\n");
        EC_POINT_free(g_x1);
        EC_POINT_free(g_x2);
        EC_POINT_free(g_x3);
        BN_free(x1);
        BN_free(x2);
        BN_free(x3);
        BN_free(x4);
        EC_GROUP_free(group);
        return 1;
    }
    printf("g^x3:\n");
    print_point_as_bn(group, g_x3);

    EC_POINT *g_x4 = EC_POINT_new(group);
    if (EC_POINT_mul(group, g_x4, x4, NULL, NULL, NULL) != 1) {
        fprintf(stderr, "Failed to compute g^x4.\n");
        EC_POINT_free(g_x1);
        EC_POINT_free(g_x2);
        EC_POINT_free(g_x3);
        EC_POINT_free(g_x4);
        BN_free(x1);
        BN_free(x2);
        BN_free(x3);
        BN_free(x4);
        EC_GROUP_free(group);
        return 1;
    }
    printf("g^x4:\n");
    print_point_as_bn(group, g_x4);

    // Compute g^x1 * g^x2 * g^x3 * g^x4
    if (EC_POINT_add(group, temp_result, g_x1, g_x2, NULL) != 1 ||
        EC_POINT_add(group, temp_result, temp_result, g_x3, NULL) != 1 ||
        EC_POINT_add(group, temp_result, temp_result, g_x4, NULL) != 1) {
        fprintf(stderr, "Failed to add EC_POINTS.\n");
        EC_POINT_free(g_x1);
        EC_POINT_free(g_x2);
        EC_POINT_free(g_x3);
        EC_POINT_free(g_x4);
        EC_POINT_free(temp_result);
        BN_free(x1);
        BN_free(x2);
        BN_free(x3);
        BN_free(x4);
        EC_GROUP_free(group);
        return 1;
    }

    printf("g^x1 * g^x2 * g^x3 * g^x4:\n");
    print_point_as_bn(group, temp_result);

    int ret = mpc_rand(results, new_seed, p);

    if (argc > 1) {
        // Handle the case where a file is passed in
        char *inputFile = argv[1];
        FILE *file;

        // Open the file
        file = fopen(inputFile, "rb");
        if (!file) {
            printf("Unable to open file: %s\n", inputFile);
            return 1;
        }

        // Define data structures to read file content
        a as[NUM_ROUNDS];
        z zs[NUM_ROUNDS];

        // Read data
        fread(&as, sizeof(a), NUM_ROUNDS, file);
        fread(&zs, sizeof(z), NUM_ROUNDS, file);

        // Close the file
        fclose(file);

        uint32_t y;
        reconstruct(as[0].yp[0], as[0].yp[1], as[0].yp[2], as[0].yp[3], &y);
        printf("Proof for rand: = %u\n", y);

        deltaFiles = clock() - begin;
        int inMilliFiles = deltaFiles * 1000 / CLOCKS_PER_SEC;
        printf("Loading files: %ju\n", (uintmax_t)inMilliFiles);

        clock_t beginE = clock(), deltaE;
        int es[NUM_ROUNDS];
        H3(y, as, NUM_ROUNDS, es);
        deltaE = clock() - beginE;
        int inMilliE = deltaE * 1000 / CLOCKS_PER_SEC;
        printf("Generating E: %ju\n", (uintmax_t)inMilliE);

        clock_t beginV = clock(), deltaV;
        for (int i = 0; i < NUM_ROUNDS; i++) {
            int verifyResult = mpc_rand_verify(as[i], es[i], zs[i]);
            if (verifyResult != 0) {
                printf("Not Verified %d\n", i);
            }
        }
        deltaV = clock() - beginV;
        int inMilliV = deltaV * 1000 / CLOCKS_PER_SEC;
        printf("Verifying: %ju\n", (uintmax_t)inMilliV);

        delta = clock() - begin;
        int inMilli = delta * 1000 / CLOCKS_PER_SEC;
        printf("Total time: %ju\n", (uintmax_t)inMilli);

    } else {
        mpz_t g, h, result_g, result_h, final_result, g_pow_x, p;
        mpz_inits(g, h, result_g, result_h, final_result, g_pow_x, p, NULL);

        // Set the modulus p
        mpz_set_ui(p, 2);   // Initialize p to 2
        mpz_pow_ui(p, p, 128);  // Set p to 2^128

        // Define the shares and shares_t arrays
        uint32_t shares[NUM_ROUNDS][4];
        uint32_t shares_t[NUM_ROUNDS][4];

        // Read data
        read_from_file("output_data.bin", g, h, shares, shares_t);
        read_com_file("out_com1.bin");

        // Compute g^x0 * g^x1 * g^x2 * g^x3 mod p
        mpz_set_ui(result_g, 1);
        for (int i = 0; i < 4; i++) {
            mpz_powm_ui(g_pow_x, g, shares[0][i], p);  // Compute g^xi mod p
            mpz_mul(result_g, result_g, g_pow_x);      // Accumulate the product
            mpz_mod(result_g, result_g, p);            // Take the modulus of the result after multiplication
        }

        // Compute t_sum
        uint32_t t_sum = 0;  // Use uint32_t type to store the accumulated result
        for (int i = 0; i < 4; i++) {
            t_sum += shares_t[0][i];  // Accumulate shares_t[0][i] to t_sum
        }

        // Take the modulus of t_sum with p
        t_sum = t_sum % MODULUS_p;

        // Compute h^t_sum mod p
        mpz_powm_ui(result_h, h, t_sum, p);  // Compute h^t_sum mod p

        // Compute the final result: Compute g^x0 * g^x1 * g^x2 * g^x3 * h^t_sum mod p
        mpz_mul(final_result, result_g, result_h);  // Compute g^x * h^t
        mpz_mod(final_result, final_result, p);     // Take the modulus of the final result

        // Output the results
        gmp_printf("g^x0 * g^x1 * g^x2 * g^x3 mod p = %Zd\n", result_g);
        gmp_printf("h^t0 * h^t1 * h^t2 * h^t3 mod p = %Zd\n", result_h);
        gmp_printf("g^x * h^t mod p = %Zd\n", final_result);

        // Clean up memory
        mpz_clears(g, h, result_g, result_h, final_result, g_pow_x, p, NULL);
    }

    end_time = clock();
    cpu_time_used = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
    printf("Execution time: %f seconds\n", cpu_time_used * 4);
    fflush(stdout);

    openmp_thread_cleanup();
    cleanup_EVP();
    return EXIT_SUCCESS;
}