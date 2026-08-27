/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_sonnet_remedium_r1_260828_010435.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
{
    static const unsigned char key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    static const unsigned char iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    static const unsigned char plaintext[] =
        "The quick brown fox jumps over the lazy dog. "
        "This is a test message for AES-256 CBC round-trip.";
    const int ptlen = (int)(sizeof(plaintext) - 1);

    BIO *mem_enc = NULL, *benc = NULL, *mem_dec = NULL, *bdec = NULL;
    unsigned char *ctbuf = NULL;
    long ctlen = 0;
    unsigned char *ctcopy = NULL;
    unsigned char outbuf[512];
    int outlen = 0, n, ret = 0;
    EVP_CIPHER_CTX *cctx = NULL;

    /* --- Encrypt side --- */
    if (!TEST_ptr(mem_enc = BIO_new(BIO_s_mem())))
        goto err;
    if (!TEST_ptr(benc = BIO_new(BIO_f_cipher()))) {
        BIO_free(mem_enc);
        goto err;
    }
    BIO_push(benc, mem_enc);

    if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (!TEST_ptr(cctx = NULL, cctx))
        ; /* placeholder no-op to keep style consistent, replaced below */

    if (!TEST_true(BIO_get_cipher_ctx(benc, &cctx)))
        goto err;
    if (!TEST_ptr(cctx))
        goto err;

    if (!TEST_int_eq(BIO_write(benc, plaintext, ptlen), ptlen))
        goto err;

    if (!TEST_int_gt(BIO_flush(benc), 0))
        goto err;

    if (!TEST_true(BIO_get_cipher_status(benc)))
        goto err;

    ctlen = BIO_get_mem_data(mem_enc, &ctbuf);
    if (!TEST_int_gt((int)ctlen, 0))
        goto err;

    /* Ciphertext length should be a multiple of AES block size (padding) */
    if (!TEST_int_eq((int)(ctlen % 16), 0))
        goto err;

    /* Save a copy of ciphertext before freeing the chain */
    if (!TEST_ptr(ctcopy = OPENSSL_memdup(ctbuf, (size_t)ctlen)))
        goto err;

    BIO_free_all(benc);
    benc = NULL;
    mem_enc = NULL;

    /* --- Decrypt side --- */
    if (!TEST_ptr(mem_dec = BIO_new_mem_buf(ctcopy, (int)ctlen)))
        goto err;
    if (!TEST_ptr(bdec = BIO_new(BIO_f_cipher()))) {
        BIO_free(mem_dec);
        goto err;
    }
    BIO_push(bdec, mem_dec);

    if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    n = BIO_read(bdec, outbuf, sizeof(outbuf));
    if (!TEST_int_ge(n, 0))
        goto err;
    outlen = n;

    /* Drain until EOF */
    while ((n = BIO_read(bdec, outbuf + outlen,
                          (int)sizeof(outbuf) - outlen)) > 0) {
        outlen += n;
        if (!TEST_int_lt(outlen, (int)sizeof(outbuf)))
            goto err;
    }

    if (!TEST_true(BIO_get_cipher_status(bdec)))
        goto err;

    if (!TEST_int_eq(outlen, ptlen))
        goto err;

    if (!TEST_mem_eq(outbuf, outlen, plaintext, ptlen))
        goto err;

    ret = 1;

err:
    OPENSSL_free(ctcopy);
    BIO_free_all(benc);
    BIO_free_all(bdec);
    return ret;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
