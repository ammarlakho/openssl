/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t1_tp1_s3_260827_152237.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    unsigned char key[32];
    unsigned char iv[16];
    const char *plaintext = "The quick brown fox jumps over the lazy dog. This is a longer string to test block boundaries!";
    int plain_len = (int)strlen(plaintext);
    unsigned char ciphertext[256];
    unsigned char decrypted[256];
    int enc_len, dec_len;
    BIO *bmem_out = NULL, *bcipher_enc = NULL;
    BIO *bmem_in = NULL, *bcipher_dec = NULL;

    memset(key, 0x01, sizeof(key));
    memset(iv, 0x02, sizeof(iv));

    /* 1. Encryption setup: Cipher BIO -> Memory BIO */
    bmem_out = BIO_new(BIO_s_mem());
    if (!TEST_ptr(bmem_out))
        goto err;

    bcipher_enc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bcipher_enc))
        goto err;

    if (!TEST_true(BIO_push(bcipher_enc, bmem_out)))
        goto err;

    if (!TEST_true(BIO_set_cipher(bcipher_enc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    /* Write plaintext and flush to handle padding/final block */
    if (!TEST_true(BIO_write(bcipher_enc, plaintext, plain_len) == plain_len))
        goto err;

    if (!TEST_true(BIO_ctrl(bcipher_enc, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    /* Read resulting ciphertext from the memory BIO */
    enc_len = BIO_read(bmem_out, ciphertext, sizeof(ciphertext));
    if (!TEST_true(enc_len > 0))
        goto err;

    BIO_free_all(bcipher_enc);
    bcipher_enc = NULL;

    /* 2. Decryption setup: Cipher BIO -> Memory BIO (initialized with ciphertext) */
    bmem_in = BIO_new_mem_buf(ciphertext, enc_len);
    if (!TEST_ptr(bmem_in))
        goto err;

    bcipher_dec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bcipher_dec))
        goto err;

    if (!TEST_true(BIO_push(bcipher_dec, bmem_in)))
        goto err;

    if (!TEST_true(BIO_set_cipher(bcipher_dec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    /* Read decrypted data */
    dec_len = BIO_read(bcipher_dec, decrypted, sizeof(decrypted));
    if (!TEST_true(dec_len == plain_len))
        goto err;

    if (!TEST_mem_eq(plaintext, plain_len, decrypted, dec_len))
        goto err;

    BIO_free_all(bcipher_dec);
    return 1;

err:
    BIO_free_all(bcipher_enc);
    BIO_free_all(bcipher_dec);
    return 0;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
