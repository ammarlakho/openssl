/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t1p2_tp1_s8_260827_154333.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    BIO *bmem = NULL, *bfilter = NULL;
    unsigned char *ct_buf = NULL;
    unsigned char *pt_buf = NULL;
    const unsigned char key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    const unsigned char iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    const char *plaintext = "The quick brown fox jumps over the lazy dog. Testing BIO cipher!";
    int pt_len = (int)strlen(plaintext);
    char *ct_ptr = NULL;
    long ct_len = 0;
    int rd_len = 0;

    /* 1. ENCRYPTION PHASE */
    bmem = BIO_new(BIO_s_mem());
    if (!TEST_ptr(bmem)) return 0;

    bfilter = BIO_push(bmem, BIO_f_cipher());
    if (!TEST_ptr(bfilter)) {
        BIO_free(bmem);
        return 0;
    }

    if (!TEST_true(BIO_set_cipher(bfilter, EVP_aes_256_cbc(), key, iv, 1))) {
        BIO_free_all(bfilter);
        return 0;
    }

    if (!TEST_true(BIO_write(bfilter, plaintext, pt_len) == pt_len)) {
        BIO_free_all(bfilter);
        return 0;
    }

    /* Must flush to ensure EVP_CipherFinal is called and padding is written to bmem */
    if (!TEST_true(BIO_ctrl(bfilter, BIO_CTRL_FLUSH, 0, NULL) == 1)) {
        BIO_free_all(bfilter);
        return 0;
    }

    ct_len = BIO_get_mem_data(bmem, &ct_ptr);
    if (ct_len <= 0) {
        BIO_free_all(bfilter);
        return 0;
    }

    ct_buf = OPENSSL_malloc(ct_len);
    if (!TEST_ptr(ct_buf)) {
        BIO_free_all(bfilter);
        return 0;
    }
    memcpy(ct_buf, ct_ptr, ct_len);

    BIO_free_all(bfilter);
    bfilter = NULL;
    bmem = NULL;

    /* 2. DECRYPTION PHASE */
    bmem = BIO_new(BIO_s_mem());
    if (!TEST_ptr(bmem)) goto err;

    /* Put ciphertext back into the source memory BIO */
    if (!TEST_true(BIO_write(bmem, ct_buf, ct_len) == (int)ct_len)) goto err;
    BIO_set_mem_offset(bmem, 0);

    bfilter = BIO_push(bmem, BIO_f_cipher());
    if (!TEST_ptr(bfilter)) goto err;

    if (!TEST_true(BIO_set_cipher(bfilter, EVP_aes_256_cbc(), key, iv, 0))) goto err;

    pt_buf = OPENSSL_malloc(ct_len + 1);
    if (!TEST_ptr(pt_buf)) goto err;

    /* Read everything from the cipher BIO */
    rd_len = BIO_read(bfilter, pt_buf, (int)ct_len);
    if (rd_len < 0) goto err;

    /* Check cipher status for authentication/padding errors */
    if (!TEST_true(BIO_ctrl(bfilter, BIO_C_GET_CIPHER_STATUS, 0, NULL) == 1)) goto err;

    /* Decrypted length should match original plaintext length */
    if (!TEST_true(rd_len == pt_len)) goto err;

    if (!TEST_mem_eq(pt_buf, rd_len, plaintext, pt_len)) goto err;

    OPENSSL_free(ct_buf);
    OPENSSL_free(pt_buf);
    BIO_free_all(bfilter);
    return 1;

err:
    if (ct_buf) OPENSSL_free(ct_buf);
    if (pt_buf) OPENSSL_free(pt_buf);
    if (bfilter) BIO_free_all(bfilter);
    else if (bmem) BIO_free(bmem);
    return 0;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
