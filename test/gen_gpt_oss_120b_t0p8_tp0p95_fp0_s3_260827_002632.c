/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p8_tp0p95_fp0_s3_260827_002632.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    const unsigned char key[32] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
        0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };
    const unsigned char iv[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    const unsigned char plaintext[] = "OpenSSL BIO cipher round‑trip test data";
    const int plen = (int)strlen((const char *)plaintext);
    unsigned char outbuf[128];
    int outlen = 0;
    BIO *bmem = NULL, *enc = NULL;
    BIO *bmem2 = NULL, *dec = NULL;
    char *enc_data = NULL;
    long enc_len = 0;
    int ret = 0;

    /* ----- Encryption side ----- */
    bmem = BIO_new(BIO_s_mem());
    if (!TEST_ptr(bmem))
        goto err;
    enc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(enc))
        goto err;
    if (!TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                 key, iv, 1)))   /* encrypt */
        goto err;
    /* Chain: enc -> bmem */
    BIO_push(enc, bmem);

    if (!TEST_int_eq(BIO_write(enc, plaintext, plen), plen))
        goto err;
    if (!TEST_int_gt(BIO_flush(enc), 0))
        goto err;

    /* Get encrypted bytes from the memory BIO */
    enc_len = BIO_get_mem_data(bmem, &enc_data);
    if (!TEST_int_gt((int)enc_len, plen))   /* ciphertext must be larger because of padding */
        goto err;

    /* ----- Decryption side ----- */
    bmem2 = BIO_new_mem_buf(enc_data, (int)enc_len);
    if (!TEST_ptr(bmem2))
        goto err;
    dec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(dec))
        goto err;
    if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                 key, iv, 0)))   /* decrypt */
        goto err;
    /* Chain: dec -> bmem2 */
    BIO_push(dec, bmem2);

    outlen = BIO_read(dec, outbuf, sizeof(outbuf));
    if (!TEST_int_gt(outlen, 0))
        goto err;
    if (!TEST_int_eq(outlen, plen))
        goto err;
    if (!TEST_mem_eq(outbuf, outlen, plaintext, plen))
        goto err;

    ret = 1;   /* success */

err:
    BIO_free_all(enc);
    BIO_free_all(dec);
    return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
