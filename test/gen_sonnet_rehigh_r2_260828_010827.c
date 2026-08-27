/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_sonnet_rehigh_r2_260828_010827.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
        "OpenSSL AES-256 CBC BIO round-trip test vector.";
    const int ptlen = (int)(sizeof(plaintext) - 1);

    BIO *benc = NULL, *bmem = NULL, *bdec = NULL, *bsrc = NULL;
    unsigned char *ctbuf1 = NULL;
    unsigned char *ctbuf1_copy = NULL;
    unsigned char *ctbuf2 = NULL;
    long ctlen1 = 0, ctlen2 = 0;
    unsigned char decbuf[512];
    int declen = 0, r, ret = 0;

    /* --- First encryption pass --- */
    if (!TEST_ptr(bmem = BIO_new(BIO_s_mem())))
        goto err;
    if (!TEST_ptr(benc = BIO_new(BIO_f_cipher())))
        goto err;
    BIO_push(benc, bmem);
    if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;
    if (!TEST_int_eq(BIO_write(benc, plaintext, ptlen), ptlen))
        goto err;
    if (!TEST_int_gt((int)BIO_flush(benc), 0))
        goto err;
    if (!TEST_true(BIO_get_cipher_status(benc)))
        goto err;

    ctlen1 = BIO_get_mem_data(bmem, &ctbuf1);
    if (!TEST_int_gt((int)ctlen1, 0))
        goto err;
    /* CBC ciphertext must be padded to a multiple of the block size */
    if (!TEST_int_eq((int)(ctlen1 % 16), 0))
        goto err;
    if (!TEST_int_ge((int)ctlen1, ptlen + 1))
        goto err;

    if (!TEST_ptr(ctbuf1_copy = OPENSSL_memdup(ctbuf1, (size_t)ctlen1)))
        goto err;

    BIO_free_all(benc);
    benc = NULL;
    bmem = NULL;

    /* --- Second encryption pass: same key/iv must be deterministic --- */
    if (!TEST_ptr(bmem = BIO_new(BIO_s_mem())))
        goto err;
    if (!TEST_ptr(benc = BIO_new(BIO_f_cipher())))
        goto err;
    BIO_push(benc, bmem);
    if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;
    if (!TEST_int_eq(BIO_write(benc, plaintext, ptlen), ptlen))
        goto err;
    if (!TEST_int_gt((int)BIO_flush(benc), 0))
        goto err;

    ctlen2 = BIO_get_mem_data(bmem, &ctbuf2);
    if (!TEST_int_eq((int)ctlen2, (int)ctlen1))
        goto err;
    if (!TEST_mem_eq(ctbuf2, (int)ctlen2, ctbuf1_copy, (int)ctlen1))
        goto err;

    BIO_free_all(benc);
    benc = NULL;
    bmem = NULL;

    /* --- Decrypt and verify round-trip against the original plaintext --- */
    if (!TEST_ptr(bsrc = BIO_new_mem_buf(ctbuf1_copy, (int)ctlen1)))
        goto err;
    if (!TEST_ptr(bdec = BIO_new(BIO_f_cipher()))) {
        BIO_free(bsrc);
        bsrc = NULL;
        goto err;
    }
    BIO_push(bdec, bsrc);
    if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    while (declen < (int)sizeof(decbuf)) {
        r = BIO_read(bdec, decbuf + declen, (int)sizeof(decbuf) - declen);
        if (r <= 0)
            break;
        declen += r;
    }
    if (!TEST_true(BIO_get_cipher_status(bdec)))
        goto err;
    if (!TEST_int_eq(declen, ptlen))
        goto err;
    if (!TEST_mem_eq(decbuf, declen, plaintext, ptlen))
        goto err;

    /* Sanity: ciphertext must not equal plaintext */
    if (!TEST_false((int)ctlen1 == ptlen
                     && memcmp(ctbuf1_copy, plaintext, (size_t)ptlen) == 0))
        goto err;

    ret = 1;

err:
    BIO_free_all(benc);
    BIO_free_all(bdec);
    OPENSSL_free(ctbuf1_copy);
    return ret;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
