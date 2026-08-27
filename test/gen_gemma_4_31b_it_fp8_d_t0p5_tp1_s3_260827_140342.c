/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p5_tp1_s3_260827_140342.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    unsigned char key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    unsigned char iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    const char *plaintext = "The quick brown fox jumps over the lazy dog";
    int plaintext_len = (int)strlen(plaintext);
    unsigned char decrypted[128];
    int decrypted_len = 0;
    BIO *b_mem = NULL, *b_enc = NULL, *b_dec = NULL;
    int ret = 0;

    /* 1. Setup Encryption Chain: Cipher BIO -> Memory BIO */
    if (!TEST_ptr((b_mem = BIO_new(BIO_s_mem()))))
        goto err;
    if (!TEST_ptr((b_enc = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_true(BIO_push(b_enc, b_mem)))
        goto err;

    /* Initialize AES-256-CBC for encryption */
    if (!TEST_true(BIO_set_cipher(b_enc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    /* Write plaintext and flush to ensure padding is processed */
    if (!TEST_true(BIO_write(b_enc, plaintext, plaintext_len) == plaintext_len))
        goto err;
    if (!TEST_true(BIO_ctrl(b_enc, BIO_CTRL_FLUSH, 0, NULL) == 1))
        goto err;

    /* 
     * We want to reuse b_mem for decryption. 
     * BIO_set_close(b_enc, 0) prevents BIO_free(b_enc) from freeing the chain.
     */
    BIO_set_close(b_enc, 0);
    BIO_free(b_enc);
    b_enc = NULL;

    /* 2. Setup Decryption Chain: Cipher BIO -> Memory BIO (containing ciphertext) */
    if (!TEST_true(BIO_reset(b_mem)))
        goto err;
    if (!TEST_ptr((b_dec = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_true(BIO_push(b_dec, b_mem)))
        goto err;

    /* Initialize AES-256-CBC for decryption */
    if (!TEST_true(BIO_set_cipher(b_dec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    /* Read decrypted data */
    decrypted_len = BIO_read(b_dec, (char *)decrypted, sizeof(decrypted));
    if (decrypted_len <= 0)
        goto err;

    /* Verify round-trip result */
    if (!TEST_mem_eq(plaintext, plaintext_len, decrypted, decrypted_len))
        goto err;

    ret = 1;

err:
    if (b_enc) BIO_free(b_enc);
    if (b_dec) BIO_free(b_dec);
    if (b_mem && b_dec == NULL) BIO_free(b_mem); /* Only free b_mem if not part of b_dec chain */

    return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
