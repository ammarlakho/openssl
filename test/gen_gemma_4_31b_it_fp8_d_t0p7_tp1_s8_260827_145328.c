/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p7_tp1_s8_260827_145328.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    unsigned char key[32], iv[16];
    unsigned char pt[] = "The quick brown fox jumps over the lazy dog";
    int pt_len = (int)strlen((char *)pt);
    unsigned char res[128] = { 0 };
    int res_len = 0;
    BIO *bmem = NULL, *benc = NULL, *bdec = NULL;
    int ok = 0;

    /* Use fixed vectors for reproducibility */
    memset(key, 0x41, sizeof(key));
    memset(iv, 0x42, sizeof(iv));

    /* 1. Setup encryption chain: BIO_f_cipher -> BIO_s_mem */
    if (!TEST_ptr(bmem = BIO_new(BIO_s_mem())))
        goto err;
    if (!TEST_ptr(benc = BIO_new(BIO_f_cipher())))
        goto err;
    if (!TEST_true(BIO_push(benc, bmem)))
        goto err;

    /* Initialize AES-256-CBC for encryption */
    if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    /* Write plaintext and flush to ensure padding is processed */
    if (!TEST_true(BIO_write(benc, (char *)pt, pt_len) == pt_len))
        goto err;
    if (!TEST_true(BIO_ctrl(benc, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    /* 2. Transition to decryption */
    /* Pop the encryption filter to leave bmem independent */
    BIO_pop(benc);
    BIO_free(benc);
    benc = NULL;

    /* Reset memory BIO offset to read from the start of ciphertext */
    if (!TEST_true(BIO_set_mem_offset(bmem, 0)))
        goto err;

    /* Setup decryption chain: BIO_f_cipher -> BIO_s_mem */
    if (!TEST_ptr(bdec = BIO_new(BIO_f_cipher())))
        goto err;
    if (!TEST_true(BIO_push(bdec, bmem)))
        goto err;

    /* Initialize AES-256-CBC for decryption */
    if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    /* Read decrypted data */
    res_len = BIO_read(bdec, (char *)res, pt_len);
    if (!TEST_true(res_len == pt_len))
        goto err;

    /* Verify round-trip result matches original plaintext */
    if (!TEST_mem_eq(pt, pt_len, res, res_len))
        goto err;

    ok = 1;

err:
    if (benc)
        BIO_free(benc);
    if (bdec)
        BIO_free_all(bdec); /* Frees the chain including bmem */
    else if (bmem)
        BIO_free(bmem);
    return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
