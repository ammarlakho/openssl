/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p3_tp1_s3_260827_132140.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    BIO *b_enc = NULL, *b_dec = NULL, *b_out = NULL;
    unsigned char *ciphertext = NULL, *decrypted = NULL;
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    unsigned char key[32] = "01234567890123456789012345678901";
    unsigned char iv[16] = "0123456789012345";
    
    /* Use a plaintext larger than ENC_MIN_CHUNK (256) to test internal buffering */
    int plaintext_len = 1024;
    unsigned char *plaintext = OPENSSL_malloc(plaintext_len);
    if (plaintext == NULL)
        return 0;
    memset(plaintext, 'A', plaintext_len);
    for (int i = 0; i < plaintext_len; i++)
        plaintext[i] = (unsigned char)(i % 256);

    /* --- Encryption Phase --- */
    b_out = BIO_new(BIO_s_mem());
    if (!TEST_ptr(b_out)) {
        ok = 0;
        goto err;
    }

    b_enc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(b_enc)) {
        ok = 0;
        goto err;
    }

    if (!TEST_true(BIO_push(b_enc, b_out))) {
        ok = 0;
        goto err;
    }

    if (!TEST_true(BIO_set_cipher(b_enc, cipher, key, iv, 1))) {
        ok = 0;
        goto err;
    }

    if (!TEST_true(BIO_write(b_enc, (char *)plaintext, plaintext_len) == plaintext_len)) {
        ok = 0;
        goto err;
    }

    /* Flush is required to process the final block and padding */
    if (!TEST_true(BIO_ctrl(b_enc, BIO_CTRL_FLUSH, 0, NULL))) {
        ok = 0;
        goto err;
    }

    int ciphertext_len = BIO_ctrl(b_out, BIO_CTRL_PENDING, 0, NULL);
    if (ciphertext_len <= 0) {
        ok = 0;
        goto err;
    }

    ciphertext = OPENSSL_malloc(ciphertext_len);
    if (ciphertext == NULL) {
        ok = 0;
        goto err;
    }

    if (!TEST_true(BIO_read(b_out, (char *)ciphertext, ciphertext_len) == ciphertext_len)) {
        ok = 0;
        goto err;
    }

    /* --- Decryption Phase --- */
    /* Create a BIO from the ciphertext memory */
    BIO *b_in = BIO_new_mem_buf(ciphertext, ciphertext_len);
    if (!TEST_ptr(b_in)) {
        ok = 0;
        goto err;
    }

    b_dec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(b_dec)) {
        ok = 0;
        goto err;
    }

    if (!TEST_true(BIO_push(b_dec, b_in))) {
        ok = 0;
        goto err;
    }

    if (!TEST_true(BIO_set_cipher(b_dec, cipher, key, iv, 0))) {
        ok = 0;
        goto err;
    }

    decrypted = OPENSSL_malloc(plaintext_len);
    if (decrypted == NULL) {
        ok = 0;
        goto err;
    }

    int read_len = 0;
    while (read_len < plaintext_len) {
        int r = BIO_read(b_dec, (char *)decrypted + read_len, plaintext_len - read_len);
        if (r <= 0)
            break;
        read_len += r;
    }

    if (!TEST_true(read_len == plaintext_len)) {
        ok = 0;
        goto err;
    }

    if (!TEST_mem_eq(plaintext, plaintext_len, decrypted, plaintext_len)) {
        ok = 0;
        goto err;
    }

err:
    OPENSSL_free(plaintext);
    OPENSSL_free(ciphertext);
    OPENSSL_free(decrypted);
    BIO_free_all(b_enc);
    BIO_free_all(b_dec);

    return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
