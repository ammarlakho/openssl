/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p6_tp1_s8_260827_143402.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    BIO *b_enc = NULL, *b_dec = NULL;
    unsigned char key[32] = {0};
    unsigned char iv[16] = {0};
    const unsigned char pt[] = "OpenSSL";
    int pt_len = (int)strlen((const char *)pt);
    
    /* Expected ciphertext for AES-256-CBC, Key=0, IV=0, PT="OpenSSL" */
    unsigned char expected_ct[] = {
        0xd1, 0xb1, 0x43, 0xd0, 0x7a, 0xd1, 0x11, 0x7d, 
        0x39, 0xb1, 0x53, 0x4c, 0x6a, 0x9b, 0xd4, 0x3b, 
        0x55, 0x8a, 0x17, 0x4d, 0x3a, 0xa1, 0x94, 0x28, 
        0x7e, 0x4c, 0x5c, 0x7d, 0x1c, 0x33, 0x8c, 0xad
    };
    int expected_ct_len = sizeof(expected_ct);
    unsigned char ct_buf[128];
    unsigned char dec_buf[128];

    /* --- Encryption Phase --- */
    b_enc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(b_enc)) return 0;

    BIO *b_mem_enc = BIO_new(BIO_s_mem());
    if (!TEST_ptr(b_mem_enc)) {
        BIO_free(b_enc);
        return 0;
    }
    BIO_push(b_enc, b_mem_enc);

    if (!TEST_true(BIO_set_cipher(b_enc, EVP_aes_256_cbc(), key, iv, 1))) {
        BIO_free(b_enc);
        return 0;
    }

    if (!TEST_true(BIO_write(b_enc, pt, pt_len) == pt_len)) {
        BIO_free(b_enc);
        return 0;
    }

    if (!TEST_true(BIO_ctrl(b_enc, BIO_CTRL_FLUSH, 0, NULL))) {
        BIO_free(b_enc);
        return 0;
    }

    /* Read encrypted data from the underlying memory BIO */
    int ct_len = BIO_read(b_mem_enc, ct_buf, sizeof(ct_buf));
    if (!TEST_true(ct_len == expected_ct_len)) {
        BIO_free(b_enc);
        return 0;
    }

    if (!TEST_mem_eq(ct_buf, ct_len, expected_ct, expected_ct_len)) {
        BIO_free(b_enc);
        return 0;
    }

    BIO_free(b_enc);

    /* --- Decryption Phase --- */
    b_dec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(b_dec)) return 0;

    BIO *b_mem_dec = BIO_new_mem_buf(ct_buf, ct_len);
    if (!TEST_ptr(b_mem_dec)) {
        BIO_free(b_dec);
        return 0;
    }
    BIO_push(b_dec, b_mem_dec);

    if (!TEST_true(BIO_set_cipher(b_dec, EVP_aes_256_cbc(), key, iv, 0))) {
        BIO_free(b_dec);
        return 0;
    }

    int dec_len = BIO_read(b_dec, dec_buf, sizeof(dec_buf));
    if (!TEST_true(dec_len == pt_len)) {
        BIO_free(b_dec);
        return 0;
    }

    if (!TEST_mem_eq(dec_buf, dec_len, pt, pt_len)) {
        BIO_free(b_dec);
        return 0;
    }

    BIO_free(b_dec);
    return 1;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
