/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p2_tp1_s3_260827_124329.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    const char *plaintext = "The quick brown fox jumps over the lazy dog";
    int plaintext_len = (int)strlen(plaintext);
    unsigned char ciphertext[128];
    unsigned char decrypted[128];
    int cipherlen = 0, dec_len = 0;
    BIO *bmem = NULL, *bcipher = NULL, *bmem_dec = NULL, *bcipher_dec = NULL;

    memset(key, 0x41, sizeof(key));
    memset(iv, 0x42, sizeof(iv));

    /* --- Encryption Phase --- */
    bmem = BIO_new(BIO_s_mem());
    if (!TEST_ptr(bmem))
        return 0;

    bcipher = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bcipher)) {
        BIO_free(bmem);
        return 0;
    }

    if (!TEST_true(BIO_push(bcipher, bmem))) {
        BIO_free_all(bcipher);
        return 0;
    }

    if (!TEST_true(BIO_set_cipher(bcipher, EVP_aes_256_cbc(), key, iv, 1))) {
        BIO_free_all(bcipher);
        return 0;
    }

    if (!TEST_true(BIO_write(bcipher, plaintext, plaintext_len) > 0)) {
        BIO_free_all(bcipher);
        return 0;
    }

    /* Flush is required to process final block/padding */
    if (!TEST_true(BIO_ctrl(bcipher, BIO_CTRL_FLUSH, 0, NULL))) {
        BIO_free_all(bcipher);
        return 0;
    }

    /* Extract ciphertext from the underlying memory BIO */
    cipherlen = BIO_read(bmem, ciphertext, sizeof(ciphertext));
    if (!TEST_true(cipherlen > 0)) {
        BIO_free_all(bcipher);
        return 0;
    }

    BIO_free_all(bcipher);

    /* --- Decryption Phase --- */
    bmem_dec = BIO_new_mem_buf(ciphertext, cipherlen);
    if (!TEST_ptr(bmem_dec))
        return 0;

    bcipher_dec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bcipher_dec)) {
        BIO_free(bmem_dec);
        return 0;
    }

    if (!TEST_true(BIO_push(bcipher_dec, bmem_dec))) {
        BIO_free_all(bcipher_dec);
        return 0;
    }

    if (!TEST_true(BIO_set_cipher(bcipher_dec, EVP_aes_256_cbc(), key, iv, 0))) {
        BIO_free_all(bcipher_dec);
        return 0;
    }

    /* Read decrypted data */
    dec_len = BIO_read(bcipher_dec, decrypted, sizeof(decrypted));
    if (!TEST_true(dec_len > 0)) {
        BIO_free_all(bcipher_dec);
        return 0;
    }

    /* Verify round-trip result */
    if (!TEST_true(dec_len == plaintext_len)) {
        BIO_free_all(bcipher_dec);
        return 0;
    }

    if (!TEST_mem_eq(plaintext, plaintext_len, decrypted, dec_len)) {
        BIO_free_all(bcipher_dec);
        return 0;
    }

    BIO_free_all(bcipher_dec);
    return 1;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
