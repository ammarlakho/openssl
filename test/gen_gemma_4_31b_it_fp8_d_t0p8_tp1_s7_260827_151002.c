/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p8_tp1_s7_260827_151002.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    unsigned char key[32] = { 0 };
    unsigned char iv[16] = { 0 };
    const char *plaintext = "The quick brown fox jumps over the lazy dog";
    int pt_len = (int)strlen(plaintext);
    unsigned char ciphertext[128];
    unsigned char decrypted[128];
    int ct_len = 0;
    int dt_len = 0;
    BIO *b_enc = NULL, *b_mem_enc = NULL;
    BIO *b_dec = NULL, *b_mem_dec = NULL;

    /* Encryption path */
    b_mem_enc = BIO_new(BIO_s_mem());
    if (!TEST_ptr(b_mem_enc))
        return 0;

    b_enc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(b_enc)) {
        BIO_free(b_mem_enc);
        return 0;
    }
    BIO_push(b_enc, b_mem_enc);

    if (!TEST_true(BIO_set_cipher(b_enc, EVP_aes_256_cbc(), key, iv, 1))) {
        BIO_free_all(b_enc);
        return 0;
    }

    if (!TEST_true(BIO_write(b_enc, plaintext, pt_len) == pt_len)) {
        BIO_free_all(b_enc);
        return 0;
    }

    if (!TEST_true(BIO_ctrl(b_enc, BIO_CTRL_FLUSH, 0, NULL))) {
        BIO_free_all(b_enc);
        return 0;
    }

    ct_len = BIO_read(b_mem_enc, ciphertext, sizeof(ciphertext));
    if (!TEST_true(ct_len > 0)) {
        BIO_free_all(b_enc);
        return 0;
    }

    /* Decryption path */
    b_mem_dec = BIO_new_mem_buf(ciphertext, ct_len);
    if (!TEST_ptr(b_mem_dec)) {
        BIO_free_all(b_enc);
        return 0;
    }

    b_dec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(b_dec)) {
        BIO_free_all(b_enc);
        BIO_free(b_mem_dec);
        return 0;
    }
    BIO_push(b_dec, b_mem_dec);

    if (!TEST_true(BIO_set_cipher(b_dec, EVP_aes_256_cbc(), key, iv, 0))) {
        BIO_free_all(b_enc);
        BIO_free_all(b_dec);
        return 0;
    }

    int r;
    while ((r = BIO_read(b_dec, decrypted + dt_len, sizeof(decrypted) - dt_len)) > 0) {
        dt_len += r;
    }

    if (!TEST_true(dt_len == pt_len)) {
        BIO_free_all(b_enc);
        BIO_free_all(b_dec);
        return 0;
    }

    if (!TEST_mem_eq(plaintext, pt_len, decrypted, dt_len)) {
        BIO_free_all(b_enc);
        BIO_free_all(b_dec);
        return 0;
    }

    if (!TEST_true(BIO_ctrl(b_dec, BIO_C_GET_CIPHER_STATUS, 0, NULL) == 1)) {
        BIO_free_all(b_enc);
        BIO_free_all(b_dec);
        return 0;
    }

    BIO_free_all(b_enc);
    BIO_free_all(b_dec);

    return 1;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
