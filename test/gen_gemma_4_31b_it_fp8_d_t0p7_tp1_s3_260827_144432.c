/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p7_tp1_s3_260827_144432.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    BIO *b_cipher_enc = NULL, *b_mem_enc = NULL;
    BIO *b_cipher_dec = NULL, *b_mem_dec = NULL;
    unsigned char pt[] = "The quick brown fox jumps over the lazy dog";
    size_t pt_len = sizeof(pt) - 1;
    unsigned char key[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };
    unsigned char iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    unsigned char ct[256];
    unsigned char dt[256];
    int ct_len = 0, dt_len = 0, r;

    /* --- Encryption Path --- */
    b_mem_enc = BIO_new(BIO_s_mem());
    if (!TEST_ptr(b_mem_enc)) return 0;

    b_cipher_enc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(b_cipher_enc)) {
        BIO_free(b_mem_enc);
        return 0;
    }

    if (!TEST_true(BIO_push(b_cipher_enc, b_mem_enc))) {
        BIO_free_all(b_cipher_enc);
        return 0;
    }

    if (!TEST_true(BIO_set_cipher(b_cipher_enc, EVP_aes_256_cbc(), key, iv, 1))) {
        BIO_free_all(b_cipher_enc);
        return 0;
    }

    if (!TEST_true(BIO_write(b_cipher_enc, pt, (int)pt_len) == (int)pt_len)) {
        BIO_free_all(b_cipher_enc);
        return 0;
    }

    /* Flush to process padding and final block */
    if (!TEST_true(BIO_ctrl(b_cipher_enc, BIO_CTRL_FLUSH, 0, NULL))) {
        BIO_free_all(b_cipher_enc);
        return 0;
    }

    /* Read the resulting ciphertext from the memory BIO */
    ct_len = BIO_read(b_mem_enc, ct, sizeof(ct));
    if (ct_len <= 0) {
        BIO_free_all(b_cipher_enc);
        return 0;
    }

    /* --- Decryption Path --- */
    b_mem_dec = BIO_new_mem_buf(ct, ct_len);
    if (!TEST_ptr(b_mem_dec)) {
        BIO_free_all(b_cipher_enc);
        return 0;
    }

    b_cipher_dec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(b_cipher_dec)) {
        BIO_free(b_mem_dec);
        BIO_free_all(b_cipher_enc);
        return 0;
    }

    if (!TEST_true(BIO_push(b_cipher_dec, b_mem_dec))) {
        BIO_free_all(b_cipher_dec);
        BIO_free_all(b_cipher_enc);
        return 0;
    }

    if (!TEST_true(BIO_set_cipher(b_cipher_dec, EVP_aes_256_cbc(), key, iv, 0))) {
        BIO_free_all(b_cipher_dec);
        BIO_free_all(b_cipher_enc);
        return 0;
    }

    /* Read decrypted data until EOF */
    while (dt_len < (int)sizeof(dt) && (r = BIO_read(b_cipher_dec, dt + dt_len, (int)sizeof(dt) - dt_len)) > 0) {
        dt_len += r;
    }

    if (!TEST_mem_eq(pt, pt_len, dt, dt_len)) {
        ok = 0;
    }

    BIO_free_all(b_cipher_enc);
    BIO_free_all(b_cipher_dec);

    return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
