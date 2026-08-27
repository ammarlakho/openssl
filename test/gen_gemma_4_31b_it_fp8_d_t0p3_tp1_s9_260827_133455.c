/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p3_tp1_s9_260827_133455.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    unsigned char key[32], iv[16];
    unsigned char plaintext[] = "The quick brown fox jumps over the lazy dog";
    int pt_len = (int)strlen((char *)plaintext);
    unsigned char result[128];
    BIO *bmem = NULL, *benc = NULL, *bdec = NULL;
    int ret = 0;

    memset(key, 0x42, sizeof(key));
    memset(iv, 0x24, sizeof(iv));
    memset(result, 0, sizeof(result));

    /* 1. Setup Encryption Chain: BIO_f_cipher -> BIO_s_mem */
    if (!TEST_ptr(bmem = BIO_new(BIO_s_mem())))
        return 0;

    if (!TEST_ptr(benc = BIO_new(BIO_f_cipher()))) {
        BIO_free(bmem);
        return 0;
    }

    if (!TEST_true(BIO_push(benc, bmem))) {
        BIO_free_all(benc);
        return 0;
    }

    /* Initialize cipher for encryption (e=1) */
    if (!TEST_true(BIO_set_cipher(benc, cipher, key, iv, 1))) {
        BIO_free_all(benc);
        return 0;
    }

    /* Write plaintext to the cipher BIO */
    if (!TEST_true(BIO_write(benc, plaintext, pt_len) == pt_len)) {
        BIO_free_all(benc);
        return 0;
    }

    /* Flush to ensure padding is written to the underlying memory BIO */
    if (!TEST_true(BIO_ctrl(benc, BIO_CTRL_FLUSH, 0, NULL))) {
        BIO_free_all(benc);
        return 0;
    }

    /* 
     * We want to reuse the memory BIO for decryption. 
     * BIO_free(benc) removes the filter but keeps the chain (bmem).
     */
    BIO_free(benc);
    benc = NULL;

    /* Reset memory BIO offset to read from the beginning of the ciphertext */
    BIO_set_mem_offset(bmem, 0);

    /* 2. Setup Decryption Chain: BIO_f_cipher -> BIO_s_mem */
    if (!TEST_ptr(bdec = BIO_new(BIO_f_cipher()))) {
        BIO_free(bmem);
        return 0;
    }

    if (!TEST_true(BIO_push(bdec, bmem))) {
        BIO_free(bdec);
        BIO_free(bmem);
        return 0;
    }

    /* Initialize cipher for decryption (e=0) */
    if (!TEST_true(BIO_set_cipher(bdec, cipher, key, iv, 0))) {
        BIO_free_all(bdec);
        return 0;
    }

    /* Read decrypted data */
    int read_len = BIO_read(bdec, (char *)result, sizeof(result));
    if (!TEST_true(read_len == pt_len)) {
        BIO_free_all(bdec);
        return 0;
    }

    /* Verify the round-trip result matches original plaintext */
    if (!TEST_mem_eq(plaintext, pt_len, result, read_len)) {
        BIO_free_all(bdec);
        return 0;
    }

    BIO_free_all(bdec);
    return 1;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
