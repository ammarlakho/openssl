/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t1p2_tp1_s4_260827_153829.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    unsigned char key[32] = "01234567890123456789012345678901";
    unsigned char iv[16] = "0123456789012345";
    const char *plaintext = "The quick brown fox jumps over the lazy dog. This is a test for BIO_f_cipher!";
    int plenv = (int)strlen(plaintext) + 1;
    unsigned char encrypted[1024];
    unsigned char decrypted[1024];
    int enclenv = 0, Declenv = 0;
    BIO *b_cipher = NULL, *b_mem = NULL;

    /* 1. Test Encryption: Plaintext -> BIO_f_cipher (ENC) -> BIO_s_mem */
    b_mem = BIO_new(BIO_s_mem());
    if (!TEST_ptr(b_mem))
        return 0;

    b_cipher = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(b_cipher)) {
        BIO_free(b_mem);
        return 0;
    }

    if (!TEST_true(BIO_push(b_cipher, b_mem))) {
        BIO_free_all(b_cipher);
        return 0;
    }

    if (!TEST_true(BIO_set_cipher(b_cipher, EVP_aes_256_cbc(), key, iv, 1))) {
        BIO_free_all(b_cipher);
        return 0;
    }

    if (!TEST_true(BIO_write(b_cipher, plaintext, plenv) > 0)) {
        BIO_free_all(b_cipher);
        return 0;
    }

    /* Flush to process the final block/padding */
    if (!TEST_true(BIO_ctrl(b_cipher, BIO_CTRL_FLUSH, 0, NULL))) {
        BIO_free_all(b_cipher);
        return 0;
    }

    /* Read the encrypted result from the memory BIO */
    enclenv = BIO_read(b_mem, encrypted, (int)sizeof(encrypted));
    if (!TEST_true(enclenv > 0)) {
        BIO_free_all(b_cipher);
        return 0;
    }

    /* 2. Test Decryption: BIO_s_mem (enc data) -> BIO_f_cipher (DEC) -> Plaintext */
    /* We'll use a new chain to ensure a clean state for decryption */
    BIO *d_mem = BIO_new(BIO_s_mem());
    if (!TEST_ptr(d_mem)) {
        BIO_free_all(b_cipher);
        return 0;
    }

    /* Load the previously encrypted data into the memory BIO source */
    if (!TEST_true(BIO_write(d_mem, encrypted, enclenv) > 0)) {
        BIO_free(d_mem);
        BIO_free_all(b_cipher);
        return 0;
    }

    BIO *d_cipher = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(d_cipher)) {
        BIO_free(d_mem);
        BIO_free_all(b_cipher);
        return 0;
    }

    if (!TEST_true(BIO_push(d_cipher, d_mem))) {
        BIO_free_all(d_cipher);
        BIO_free_all(b_cipher);
        return 0;
    }

    if (!TEST_true(BIO_set_cipher(d_cipher, EVP_aes_256_cbc(), key, iv, 0))) {
        BIO_free_all(d_cipher);
        BIO_free_all(b_cipher);
        return 0;
    }

    /* Read through the decryption filter */
    Declenv = BIO_read(d_cipher, decrypted, (int)sizeof(decrypted));
    /* Flush is critical to retrieve the decrypted padded block */
    BIO_ctrl(d_cipher, BIO_CTRL_FLUSH, 0, NULL);
    
    /* Re-read any remnants after flush if read hasn't finished */
    int extra = BIO_read(d_cipher, decrypted + Declenv, (int)sizeof(decrypted) - Declenv);
    Declenv += extra;

    if (!TEST_mem_eq(plaintext, plenv, decrypted, Declenv)) {
        BIO_free_all(d_cipher);
        BIO_free_all(b_cipher);
        return 0;
    }

    BIO_free_all(d_cipher);
    BIO_free_all(b_cipher);
    return 1;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
