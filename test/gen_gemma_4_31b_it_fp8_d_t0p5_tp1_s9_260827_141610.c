/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p5_tp1_s9_260827_141610.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    unsigned char key[32], iv[16];
    const char *plaintext = "The quick brown fox jumps over the lazy dog";
    int plaintext_len = (int)strlen(plaintext);
    BIO *benc = NULL, *bmem = NULL, *bdec = NULL, *bmem_dec = NULL;
    char *ciphertext = NULL;
    long ct_len = 0;
    unsigned char decrypted[128];
    int decrypted_len = 0;

    /* Initialize key and IV with fixed values for reproducibility */
    memset(key, 0x01, 32);
    memset(iv, 0x02, 16);

    /* --- Encryption Phase --- */
    /* Create a chain: BIO_f_cipher -> BIO_s_mem */
    if (!TEST_ptr(bmem = BIO_new(BIO_s_mem())))
        goto err;
    if (!TEST_ptr(benc = BIO_new(BIO_f_cipher())))
        goto err;
    if (!TEST_true(BIO_push(benc, bmem)))
        goto err;

    /* Configure the cipher BIO for encryption */
    if (!TEST_true(BIO_set_cipher(benc, cipher, key, iv, 1)))
        goto err;

    /* Write plaintext; the cipher BIO encrypts and pushes to the memory BIO */
    if (!TEST_true(BIO_write(benc, plaintext, plaintext_len) == plaintext_len))
        goto err;

    /* Flush is mandatory to process the final block and padding */
    if (!TEST_true(BIO_ctrl(benc, BIO_CTRL_FLUSH, 0, NULL) > 0))
        goto err;

    /* Extract the encrypted data from the memory BIO */
    ct_len = BIO_get_mem_data(bmem, &ciphertext);
    if (ct_len <= 0)
        goto err;

    /* --- Decryption Phase --- */
    /* Create a chain: BIO_f_cipher -> BIO_s_mem (reading from ciphertext) */
    if (!TEST_ptr(bmem_dec = BIO_new_mem_buf(ciphertext, ct_len)))
        goto err;
    if (!TEST_ptr(bdec = BIO_new(BIO_f_cipher())))
        goto err;
    if (!TEST_true(BIO_push(bdec, bmem_dec)))
        goto err;

    /* Configure the cipher BIO for decryption */
    if (!TEST_true(BIO_set_cipher(bdec, cipher, key, iv, 0)))
        goto err;

    /* Read from the cipher BIO; it reads encrypted data and decrypts it */
    decrypted_len = BIO_read(bdec, decrypted, sizeof(decrypted));
    if (!TEST_true(decrypted_len == plaintext_len))
        goto err;

    /* Verify the round-trip result matches the original plaintext */
    if (!TEST_mem_eq(plaintext, plaintext_len, decrypted, decrypted_len))
        goto err;

    BIO_free_all(benc);
    BIO_free_all(bdec);
    return 1;

err:
    BIO_free_all(benc);
    BIO_free_all(bdec);
    return 0;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
