/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p5_tp1_s2_260827_140214.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    int ret = 0;
    BIO *b_enc = NULL, *b_mem_enc = NULL;
    BIO *b_dec = NULL, *b_mem_dec = NULL;
    unsigned char key[32] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                              0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                              0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                              0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
    unsigned char iv[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const char *plain = "The quick brown fox jumps over the lazy dog";
    int plain_len = (int)strlen(plain);
    unsigned char ciphertext[128];
    unsigned char decrypted[128];
    int ct_len = 0, dec_len = 0;

    /* 1. Encryption Path */
    b_mem_enc = BIO_new(BIO_s_mem());
    if (!TEST_ptr(b_mem_enc))
        goto err;

    b_enc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(b_enc))
        goto err;

    if (!TEST_true(BIO_push(b_enc, b_mem_enc)))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_enc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (!TEST_true(BIO_write(b_enc, plain, plain_len) > 0))
        goto err;

    /* Flush to ensure padding is processed and written to the memory BIO */
    if (!TEST_true(BIO_ctrl(b_enc, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    ct_len = BIO_read(b_mem_enc, ciphertext, sizeof(ciphertext));
    if (!TEST_true(ct_len > 0))
        goto err;

    /* 2. Decryption Path */
    /* Use a memory BIO initialized with the ciphertext */
    b_mem_dec = BIO_new_mem_buf(ciphertext, ct_len);
    if (!TEST_ptr(b_mem_dec))
        goto err;

    b_dec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(b_dec))
        goto err;

    if (!TEST_true(BIO_push(b_dec, b_mem_dec)))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_dec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    dec_len = BIO_read(b_dec, decrypted, sizeof(decrypted));
    if (!TEST_true(dec_len > 0))
        goto err;

    /* 3. Verification */
    if (!TEST_mem_eq(plain, plain_len, decrypted, dec_len))
        goto err;

    ret = 1;

err:
    BIO_free_all(b_enc);
    BIO_free_all(b_dec);
    return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
