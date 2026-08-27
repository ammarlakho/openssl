/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p4_tp1_s8_260827_135520.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    int ok = 1;
    BIO *b_enc = NULL, *b_mem_enc = NULL;
    BIO *b_dec = NULL, *b_mem_dec = NULL;
    unsigned char key[32], iv[16];
    unsigned char ciphertext[256], decrypted[256];
    const char *plaintext = "The quick brown fox jumps over the lazy dog";
    int pt_len = (int)strlen(plaintext);
    int ct_len, dt_len;

    /* Initialize key and IV with fixed values */
    memset(key, 0x42, sizeof(key));
    memset(iv, 0x24, sizeof(iv));

    /* Setup Encryption Chain: BIO_f_cipher -> BIO_s_mem */
    b_mem_enc = BIO_new(BIO_s_mem());
    if (!TEST_ptr(b_mem_enc)) {
        ok = 0;
        goto cleanup;
    }

    b_enc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(b_enc)) {
        ok = 0;
        goto cleanup;
    }

    if (!TEST_true(BIO_push(b_enc, b_mem_enc) != NULL)) {
        ok = 0;
        goto cleanup;
    }

    if (!TEST_true(BIO_set_cipher(b_enc, EVP_aes_256_cbc(), key, iv, 1))) {
        ok = 0;
        goto cleanup;
    }

    /* Encrypt data */
    if (!TEST_true(BIO_write(b_enc, plaintext, pt_len) == pt_len)) {
        ok = 0;
        goto cleanup;
    }

    /* Flush to process padding and final block */
    if (!TEST_true(BIO_ctrl(b_enc, BIO_CTRL_FLUSH, 0, NULL) == 1)) {
        ok = 0;
        goto cleanup;
    }

    /* Extract ciphertext from the memory BIO */
    ct_len = BIO_read(b_mem_enc, (char *)ciphertext, sizeof(ciphertext));
    if (!TEST_true(ct_len > 0)) {
        ok = 0;
        goto cleanup;
    }

    /* Setup Decryption Chain: BIO_f_cipher -> BIO_s_mem */
    b_mem_dec = BIO_new(BIO_s_mem());
    if (!TEST_ptr(b_mem_dec)) {
        ok = 0;
        goto cleanup;
    }

    /* Write the ciphertext into the memory BIO for the cipher BIO to read */
    if (!TEST_true(BIO_write(b_mem_dec, ciphertext, ct_len) == ct_len)) {
        ok = 0;
        goto cleanup;
    }

    b_dec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(b_dec)) {
        ok = 0;
        goto cleanup;
    }

    if (!TEST_true(BIO_push(b_dec, b_mem_dec) != NULL)) {
        ok = 0;
        goto cleanup;
    }

    if (!TEST_true(BIO_set_cipher(b_dec, EVP_aes_256_cbc(), key, iv, 0))) {
        ok = 0;
        goto cleanup;
    }

    /* Decrypt data */
    dt_len = BIO_read(b_dec, (char *)decrypted, sizeof(decrypted));
    if (!TEST_true(dt_len == pt_len)) {
        ok = 0;
        goto cleanup;
    }

    /* Verify the result matches the original plaintext */
    if (!TEST_mem_eq(plaintext, pt_len, decrypted, dt_len)) {
        ok = 0;
        goto cleanup;
    }

cleanup:
    if (b_enc) BIO_free(b_enc);
    if (b_dec) BIO_free(b_dec);
    /* Note: BIO_push transfers ownership, so BIO_free(b_enc) frees b_mem_enc */

    return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
