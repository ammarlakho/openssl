/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t1p2_tp1_s10_260827_154614.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    int plain_len = (int)strlen(plaintext);
    char decrypted[1024] = { 0 };
    int dec_len = 0;
    BIO *b_enc = NULL, *b_dec = NULL, *b_mem = NULL;
    char *ct_ptr = NULL;
    long ct_len = 0;

    /* Encryption Phase */
    b_mem = BIO_new(BIO_s_mem());
    if (!TEST_ptr(b_mem))
        return 0;

    b_enc = BIO_push(BIO_f_cipher(), b_mem);
    if (!TEST_ptr(b_enc)) {
        BIO_free(b_mem);
        return 0;
    }

    if (!TEST_true(BIO_set_cipher(b_enc, EVP_aes_256_cbc(), key, iv, 1))) {
        BIO_free_all(b_enc);
        return 0;
    }

    if (!TEST_true(BIO_write(b_enc, plaintext, plain_len) == plain_len)) {
        BIO_free_all(b_enc);
        return 0;
    }

    /* Finalize encryption to handle padding */
    if (!TEST_true(BIO_ctrl(b_enc, BIO_CTRL_FLUSH, 0, NULL))) {
        BIO_free_all(b_enc);
        return 0;
    }

    ct_len = BIO_get_mem_data(b_mem, &ct_ptr);
    if (ct_len <= 0) {
        BIO_free_all(b_enc);
        return 0;
    }

    /* Decryption Phase */
    /* Use a new memory BIO for the source ciphertext */
    BIO *b_src = BIO_new(BIO_s_mem());
    if (!TEST_ptr(b_src)) {
        BIO_free_all(b_enc);
        return 0;
    }
    BIO_write(b_src, ct_ptr, (int)ct_len);

    b_dec = BIO_push(BIO_f_cipher(), b_src);
    if (!TEST_ptr(b_dec)) {
        BIO_free_all(b_enc);
        BIO_free(b_src);
        return 0;
    }

    if (!TEST_true(BIO_set_cipher(b_dec, EVP_aes_256_cbc(), key, iv, 0))) {
        BIO_free_all(b_enc);
        BIO_free_all(b_dec);
        return 0;
    }

    /* Read decrypted data incrementally to exercise the BIO buffer logic */
    int n;
    while ((n = BIO_read(b_dec, decrypted + dec_len, sizeof(decrypted) - dec_len - 1)) > 0) {
        dec_len += n;
    }

    BIO_free_all(b_enc);
    BIO_free_all(b_dec);

    /* Verify round-trip */
    if (!TEST_true(dec_len == plain_len))
        return 0;

    return TEST_mem_eq(plaintext, plain_len, decrypted, dec_len);
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
