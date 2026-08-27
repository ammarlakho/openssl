/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t1_tp1_s4_260827_152412.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    int ok = 0;
    BIO *b_enc = NULL, *b_mem_enc = NULL;
    BIO *b_dec = NULL, *b_mem_dec = NULL;
    const unsigned char key[32] = "01234567890123456789012345678901";
    const unsigned char iv[16] = "0123456789012345";
    const char *plaintext = "The quick brown fox jumps over the lazy dog - OpenSSL BIO Cipher Test";
    int pt_len = (int)strlen(plaintext);
    unsigned char ciphertext[256];
    unsigned char decrypted[256];
    int ct_len = 0, dt_len = 0;

    /* 1. Setup Encryption Chain: BIO_f_cipher -> BIO_s_mem */
    b_mem_enc = BIO_new(BIO_s_mem());
    if (!TEST_ptr(b_mem_enc))
        goto err;

    b_enc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(b_enc))
        goto err;

    if (!TEST_true(BIO_push(b_enc, b_mem_enc)))
        goto err;

    /* Configure for AES-256-CBC Encryption */
    if (!TEST_true(BIO_set_cipher(b_enc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    /* Write plaintext to the filter BIO */
    if (!TEST_true(BIO_write(b_enc, plaintext, pt_len) == pt_len))
        goto err;

    /* Flush the cipher BIO to process final block and padding */
    if (!TEST_true(BIO_ctrl(b_enc, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    /* Extract ciphertext from the underlying memory BIO */
    ct_len = BIO_read(b_mem_enc, ciphertext, sizeof(ciphertext));
    if (!TEST_true(ct_len > 0))
        goto err;

    /* 2. Setup Decryption Chain: BIO_f_cipher -> BIO_s_mem */
    b_mem_dec = BIO_new(BIO_s_mem());
    if (!TEST_ptr(b_mem_dec))
        goto err;

    /* Load the ciphertext into the source memory BIO */
    if (!TEST_true(BIO_write(b_mem_dec, ciphertext, ct_len) == ct_len))
        goto err;

    b_dec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(b_dec))
        goto err;

    if (!TEST_true(BIO_push(b_dec, b_mem_dec)))
        goto err;

    /* Configure for AES-256-CBC Decryption */
    if (!TEST_true(BIO_set_cipher(b_dec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    /* Read from the filter BIO; this should trigger decryption and final block processing */
    dt_len = BIO_read(b_dec, decrypted, sizeof(decrypted));
    if (!TEST_true(dt_len == pt_len))
        goto err;

    /* Compare result with original plaintext */
    if (!TEST_mem_eq(plaintext, pt_len, decrypted, dt_len))
        goto err;

    ok = 1;

err:
    BIO_free(b_enc);
    BIO_free(b_dec);
    return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
