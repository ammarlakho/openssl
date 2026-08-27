/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_sonnet_remedium_r2_260828_010455.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };
    static const unsigned char iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    static const unsigned char plaintext[16] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };
    static const unsigned char expected_ct[16] = {
        0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba,
        0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6
    };
    BIO *benc = NULL, *bmem = NULL, *bchain = NULL;
    BIO *bdec = NULL, *bmemin = NULL, *bchain2 = NULL;
    EVP_CIPHER_CTX *cctx;
    unsigned char outbuf[64];
    int outlen;
    const unsigned char *memdata;
    long memlen;
    int ok = 0;

    benc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(benc))
        goto err;
    bmem = BIO_new(BIO_s_mem());
    if (!TEST_ptr(bmem))
        goto err;

    if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    cctx = BIO_get_cipher_ctx(benc);
    if (!TEST_ptr(cctx))
        goto err;
    if (!TEST_true(EVP_CIPHER_CTX_set_padding(cctx, 0)))
        goto err;

    bchain = BIO_push(benc, bmem);
    if (!TEST_ptr(bchain))
        goto err;

    if (!TEST_int_eq(BIO_write(bchain, plaintext, sizeof(plaintext)),
                      (int)sizeof(plaintext)))
        goto err;

    if (!TEST_int_gt(BIO_flush(bchain), 0))
        goto err;

    memlen = BIO_get_mem_data(bmem, &memdata);
    if (!TEST_int_eq((int)memlen, (int)sizeof(expected_ct)))
        goto err;
    if (!TEST_mem_eq(memdata, (int)memlen, expected_ct, sizeof(expected_ct)))
        goto err;

    /* Now decrypt the fixed ciphertext vector back through a cipher BIO */
    bdec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bdec))
        goto err;
    bmemin = BIO_new_mem_buf(expected_ct, sizeof(expected_ct));
    if (!TEST_ptr(bmemin))
        goto err;

    if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    cctx = BIO_get_cipher_ctx(bdec);
    if (!TEST_ptr(cctx))
        goto err;
    if (!TEST_true(EVP_CIPHER_CTX_set_padding(cctx, 0)))
        goto err;

    bchain2 = BIO_push(bdec, bmemin);
    if (!TEST_ptr(bchain2))
        goto err;

    outlen = BIO_read(bchain2, outbuf, sizeof(outbuf));
    if (!TEST_int_eq(outlen, (int)sizeof(plaintext)))
        goto err;
    if (!TEST_mem_eq(outbuf, outlen, plaintext, sizeof(plaintext)))
        goto err;

    if (!TEST_true(BIO_get_cipher_status(bdec)))
        goto err;

    ok = 1;

err:
    /* bmem is owned by the bchain once pushed; freeing benc frees the chain */
    BIO_free_all(bchain != NULL ? bchain : benc);
    BIO_free_all(bchain2 != NULL ? bchain2 : bdec);
    return ok;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
