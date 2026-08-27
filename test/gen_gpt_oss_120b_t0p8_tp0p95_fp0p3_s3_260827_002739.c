/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p8_tp0p95_fp0p3_s3_260827_002739.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
static int test_bio_enc_generated(void)
{
    /* Test vector (AES‑256‑CBC, no padding) */
    static const unsigned char key[32] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
        0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };
    static const unsigned char iv[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const unsigned char plaintext[] = "Sixteen byte txt";
    static const unsigned char expected_ct[16] = {
        0xf5,0x8c,0x4c,0x04,0xd6,0xe5,0xf1,0xba,
        0x77,0x9e,0xab,0xfb,0x5f,0x7b,0xfb,0xd6
    };

    int ok = 0;
    BIO *bmem = NULL, *bcipher = NULL;
    char *out = NULL;
    int outlen = 0;

    /* ---------- encryption ---------- */
    bmem = BIO_new(BIO_s_mem());
    if (!TEST_ptr(bmem))
        goto cleanup;
    bcipher = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bcipher))
        goto cleanup;
    if (!TEST_true(BIO_set_cipher(bcipher, EVP_aes_256_cbc(),
                                 key, iv, 1)))
        goto cleanup;
    /* disable padding to match the test vector */
    if (!TEST_true(BIO_ctrl(bcipher, BIO_C_SET_PADDING, 0, NULL)))
        goto cleanup;

    BIO_push(bcipher, bmem);
    if (!TEST_int_eq(BIO_write(bcipher,
                               plaintext,
                               (int)sizeof(plaintext) - 1),
                     (int)sizeof(plaintext) - 1))
        goto cleanup;
    if (!TEST_true(BIO_flush(bcipher)))
        goto cleanup;

    outlen = BIO_get_mem_data(bmem, &out);
    if (!TEST_int_eq(outlen, (int)sizeof(expected_ct)))
        goto cleanup;
    if (!TEST_mem_eq(out, outlen, expected_ct, sizeof(expected_ct)))
        goto cleanup;

    BIO_free_all(bcipher);
    bcipher = NULL;
    BIO_free(bmem);
    bmem = NULL;

    /* ---------- decryption ---------- */
    bmem = BIO_new_mem_buf(expected_ct, (int)sizeof(expected_ct));
    if (!TEST_ptr(bmem))
        goto cleanup;
    bcipher = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bcipher))
        goto cleanup;
    if (!TEST_true(BIO_set_cipher(bcipher, EVP_aes_256_cbc(),
                                 key, iv, 0)))
        goto cleanup;
    if (!TEST_true(BIO_ctrl(bcipher, BIO_C_SET_PADDING, 0, NULL)))
        goto cleanup;

    BIO_push(bcipher, bmem);
    unsigned char decbuf[64];
    int readlen = BIO_read(bcipher, decbuf, sizeof(decbuf));
    if (!TEST_int_gt(readlen, 0))
        goto cleanup;
    if (!TEST_int_eq(readlen, (int)sizeof(plaintext) - 1))
        goto cleanup;
    if (!TEST_mem_eq(decbuf, readlen,
                     plaintext, sizeof(plaintext) - 1))
        goto cleanup;

    ok = 1; /* all checks passed */

cleanup:
    BIO_free_all(bcipher);
    BIO_free_all(bmem);
    return ok;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
