/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_sonnet_remedium_r8_260828_010640.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    static const unsigned char key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    static const unsigned char iv[16] = {
        0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00
    };
    static const unsigned char plaintext[] =
        "The quick brown fox jumps over the lazy dog. "
        "This is a fixed test vector for AES-256 CBC round trip "
        "testing through the BIO_f_cipher() filter BIO.";
    const int ptlen = (int)(sizeof(plaintext) - 1);

    BIO *benc = NULL, *bmem = NULL, *bdec = NULL, *bmem2 = NULL;
    unsigned char cipherbuf[4096];
    unsigned char decbuf[4096];
    int clen = 0, n, dlen = 0;
    int ret = 0;

    /* --- Encrypt path: mem BIO <- cipher BIO --- */
    if (!TEST_ptr(bmem = BIO_new(BIO_s_mem())))
        goto err;
    if (!TEST_ptr(benc = BIO_new(BIO_f_cipher())))
        goto err;
    if (!TEST_ptr(BIO_push(benc, bmem)))
        goto err;
    if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(), key, iv, 1 /* encrypt */)))
        goto err;

    if (!TEST_int_eq(BIO_write(benc, plaintext, ptlen), ptlen))
        goto err;
    if (!TEST_int_gt(BIO_flush(benc), 0))
        goto err;

    n = BIO_read(bmem, cipherbuf, sizeof(cipherbuf));
    if (!TEST_int_gt(n, 0))
        goto err;
    clen = n;

    /* Ciphertext should differ from plaintext and be block-aligned */
    if (!TEST_int_eq(clen % 16, 0))
        goto err;
    if (!TEST_mem_ne(cipherbuf, (size_t)ptlen < (size_t)clen ? (size_t)ptlen : (size_t)clen,
                      plaintext, (size_t)ptlen < (size_t)clen ? (size_t)ptlen : (size_t)clen))
        goto err;

    BIO_free(benc);
    benc = NULL;
    BIO_free(bmem);
    bmem = NULL;

    /* --- Decrypt path: mem BIO (with ciphertext) <- cipher BIO --- */
    if (!TEST_ptr(bmem2 = BIO_new_mem_buf(cipherbuf, clen)))
        goto err;
    if (!TEST_ptr(bdec = BIO_new(BIO_f_cipher())))
        goto err;
    if (!TEST_ptr(BIO_push(bdec, bmem2)))
        goto err;
    if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(), key, iv, 0 /* decrypt */)))
        goto err;

    n = BIO_read(bdec, decbuf, sizeof(decbuf));
    if (!TEST_int_gt(n, 0))
        goto err;
    dlen = n;

    if (!TEST_int_eq(dlen, ptlen))
        goto err;
    if (!TEST_mem_eq(decbuf, dlen, plaintext, ptlen))
        goto err;

    /* Verify cipher status reports ok after full decrypt */
    if (!TEST_long_eq(BIO_get_cipher_status(bdec), 1))
        goto err;

    ret = 1;

err:
    BIO_free(bdec);
    BIO_free(bmem2);
    BIO_free(benc);
    BIO_free(bmem);
    return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
