/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p8_tp1_s5_260827_150545.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    /* 
     * Scenario: AES-256 CBC BIO round-trip.
     * Tests the BIO_f_cipher filter by encrypting a buffer larger than 
     * ENC_BLOCK_SIZE to exercise the internal buffering and flushing logic.
     */
    int ok = 0;
    BIO *b_enc = NULL, *b_mem = NULL;
    BIO *b_dec = NULL, *b_mdec = NULL;
    unsigned char *pt = NULL, *ct_ptr = NULL, *res = NULL;
    unsigned char key[32], iv[16];
    int pt_len = 5000; /* Greater than ENC_BLOCK_SIZE (4096) */
    int res_len = 0;

    /* Setup deterministic key and IV */
    memset(key, 0x42, sizeof(key));
    memset(iv, 0x24, sizeof(iv));

    pt = OPENSSL_malloc(pt_len);
    res = OPENSSL_malloc(pt_len + 16); /* Space for padding */
    if (pt == NULL || res == NULL)
        goto err;
    memset(pt, 'A', pt_len);

    /* --- Encryption Phase --- */
    b_enc = BIO_new(BIO_f_cipher());
    b_mem = BIO_new(BIO_s_mem());
    if (!TEST_ptr(b_enc) || !TEST_ptr(b_mem))
        goto err;

    if (!TEST_true(BIO_push(b_enc, b_mem)))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_enc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    /* Write plaintext to encrypt */
    if (!TEST_true(BIO_write(b_enc, (char *)pt, pt_len) == pt_len))
        goto err;

    /* BIO_CTRL_FLUSH is required to trigger EVP_CipherFinal_ex and push padding */
    if (!TEST_true(BIO_ctrl(b_enc, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    /* Extract ciphertext from the memory BIO */
    long ct_len = BIO_get_mem_data(b_mem, &ct_ptr);
    if (ct_len <= 0)
        goto err;

    /* --- Decryption Phase --- */
    b_dec = BIO_new(BIO_f_cipher());
    b_mdec = BIO_new_mem_buf(ct_ptr, ct_len);
    if (!TEST_ptr(b_dec) || !TEST_ptr(b_mdec))
        goto err;

    if (!TEST_true(BIO_push(b_dec, b_mdec)))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_dec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    /* Read until EOF to ensure all data (including final block) is processed */
    while ((res_len = BIO_read(b_dec, (char *)res, pt_len + 16)) > 0) {
        /* 
         * Since BIO_read might return partials, we'd usually accumulate.
         * For this buffer size and mem BIO, it should return all in one or a 
         * few calls. Let's just read until empty.
         */
        if (res_len == pt_len)
            break;
    }
    
    /* If we didn't get exactly pt_len in one go, we just need the total sum.
     * Let's refine the read to be robust. */
    res_len = 0;
    int r;
    while ((r = BIO_read(b_dec, (char *)res + res_len, (pt_len + 16) - res_len)) > 0) {
        res_len += r;
    }

    /* Verify the decrypted plaintext matches the original */
    if (!TEST_mem_eq(res, res_len, pt, pt_len))
        goto err;

    /* Verify cipher status (should be 1 for successful decryption) */
    if (!TEST_true(BIO_ctrl(b_dec, BIO_C_GET_CIPHER_STATUS, 0, NULL) == 1))
        goto err;

    ok = 1;

err:
    if (b_enc) BIO_free_all(b_enc);
    if (b_dec) BIO_free_all(b_dec);
    if (pt) OPENSSL_free(pt);
    if (res) OPENSSL_free(res);
    return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
