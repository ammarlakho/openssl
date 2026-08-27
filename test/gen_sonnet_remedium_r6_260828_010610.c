/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_sonnet_remedium_r6_260828_010610.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
        "Pack my box with five dozen liquor jugs. 1234567890";
    const int plen = (int)(sizeof(plaintext) - 1);

    BIO *benc = NULL, *bmem = NULL, *bdec = NULL, *bmem2 = NULL;
    unsigned char cbuf[1024];
    unsigned char dbuf[1024];
    int clen = 0, dlen = 0, n;
    int ret = 0;

    /* Encrypt path: cipher BIO pushed on top of a mem BIO */
    if (!TEST_ptr(bmem = BIO_new(BIO_s_mem())))
        goto err;
    if (!TEST_ptr(benc = BIO_new(BIO_f_cipher())))
        goto err;
    if (!TEST_ptr(BIO_push(benc, bmem)))
        goto err;
    if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (!TEST_int_eq(BIO_write(benc, plaintext, plen), plen))
        goto err;
    if (!TEST_int_ge(BIO_flush(benc), 0))
        goto err;

    clen = BIO_read(bmem, cbuf, sizeof(cbuf));
    if (!TEST_int_gt(clen, 0))
        goto err;

    /* Ciphertext should differ from plaintext (sanity) */
    if (!TEST_false(clen == plen && memcmp(cbuf, plaintext, plen) == 0))
        goto err;

    BIO_free(benc);
    benc = NULL;
    bmem = NULL; /* freed as part of chain */

    /* Decrypt path */
    if (!TEST_ptr(bmem2 = BIO_new(BIO_s_mem())))
        goto err;
    if (!TEST_int_eq(BIO_write(bmem2, cbuf, clen), clen))
        goto err;

    if (!TEST_ptr(bdec = BIO_new(BIO_f_cipher())))
        goto err;
    if (!TEST_ptr(BIO_push(bdec, bmem2)))
        goto err;
    if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    n = BIO_read(bdec, dbuf, sizeof(dbuf));
    if (!TEST_int_gt(n, 0))
        goto err;
    dlen = n;

    if (!TEST_true(BIO_get_cipher_status(bdec)))
        goto err;

    if (!TEST_mem_eq(dbuf, dlen, plaintext, plen))
        goto err;

    ret = 1;

err:
    BIO_free(benc);
    BIO_free(bmem);
    BIO_free(bdec);
    BIO_free(bmem2);
    return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
