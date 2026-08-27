/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p7_tp1_s9_260827_145615.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    unsigned char pt[] = "The quick brown fox jumps over the lazy dog. This is a test of BIO_f_cipher.";
    int pt_len = (int)sizeof(pt) - 1;
    unsigned char ct[256];
    unsigned char decrypted[256];
    int ct_len = 0, dec_len = 0;
    BIO *b_enc = NULL, *b_dec = NULL, *b_mem = NULL;

    memset(key, 0x01, sizeof(key));
    memset(iv, 0x02, sizeof(iv));

    /* --- Encryption Phase --- */
    b_mem = BIO_new(BIO_s_mem());
    if (!TEST_ptr(b_mem))
        return 0;

    b_enc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(b_enc))
        goto err;

    if (!TEST_true(BIO_push(b_enc, b_mem)))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_enc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (!TEST_true(BIO_write(b_enc, (const char *)pt, pt_len) > 0))
        goto err;

    /* Flush to ensure padding is processed and written to b_mem */
    if (!TEST_true(BIO_ctrl(b_enc, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    /* Read encrypted data from the memory BIO */
    BIO_set_mem_offset(b_mem, 0);
    ct_len = BIO_read(b_mem, ct, sizeof(ct));
    if (!TEST_true(ct_len > 0))
        goto err;

    /* --- Decryption Phase --- */
    /* Use a new memory BIO initialized with the ciphertext */
    BIO *b_mem_in = BIO_new_mem_buf(ct, ct_len);
    if (!TEST_ptr(b_mem_in))
        goto err;

    b_dec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(b_dec)) {
        BIO_free(b_mem_in);
        goto err;
    }

    if (!TEST_true(BIO_push(b_dec, b_mem_in))) {
        BIO_free_all(b_dec);
        goto err;
    }

    if (!TEST_true(BIO_set_cipher(b_dec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    dec_len = BIO_read(b_dec, (char *)decrypted, sizeof(decrypted));
    if (!TEST_true(dec_len > 0))
        goto err;

    /* Verify round-trip result */
    if (!TEST_mem_eq(pt, pt_len, decrypted, dec_len))
        goto err;

    BIO_free_all(b_enc);
    BIO_free_all(b_dec);
    return 1;

err:
    if (b_enc) BIO_free_all(b_enc);
    if (b_dec) BIO_free_all(b_dec);
    if (b_mem && b_enc == NULL) BIO_free(b_mem);
    return 0;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
