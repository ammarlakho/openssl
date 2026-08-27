/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_sonnet_relow_r2_260828_010244.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x00
    };
    static const unsigned char plaintext[] =
        "The quick brown fox jumps over the lazy dog. "
        "Pack my box with five dozen liquor jugs.";
    unsigned char ciphertext[256];
    unsigned char decrypted[256];
    int ctlen = 0, ctlen2 = 0, total_ct = 0;
    int dtlen = 0, dtlen2 = 0, total_dt = 0;
    BIO *benc = NULL, *bmem = NULL;
    BIO *bdec = NULL, *bmem2 = NULL;
    int ret = 0;

    /* --- Encrypt path --- */
    if (!TEST_ptr(bmem = BIO_new(BIO_s_mem())))
        goto err;
    if (!TEST_ptr(benc = BIO_new(BIO_f_cipher())))
        goto err;
    if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    BIO_push(benc, bmem);

    if (!TEST_int_eq(BIO_write(benc, plaintext, (int)sizeof(plaintext)),
                      (int)sizeof(plaintext)))
        goto err;

    if (!TEST_int_ge(BIO_flush(benc), 0))
        goto err;

    if (!TEST_true(BIO_get_cipher_status(benc)))
        goto err;

    ctlen = BIO_read(bmem, ciphertext, sizeof(ciphertext));
    if (!TEST_int_gt(ctlen, 0))
        goto err;

    /* Ciphertext should differ from plaintext */
    if (!TEST_true(ctlen != (int)sizeof(plaintext)
                   || memcmp(ciphertext, plaintext, sizeof(plaintext)) != 0))
        goto err;

    BIO_free(benc);
    benc = NULL;
    bmem = NULL; /* freed as part of chain */

    /* --- Decrypt path --- */
    if (!TEST_ptr(bmem2 = BIO_new(BIO_s_mem())))
        goto err;
    if (!TEST_int_eq(BIO_write(bmem2, ciphertext, ctlen), ctlen))
        goto err;

    if (!TEST_ptr(bdec = BIO_new(BIO_f_cipher())))
        goto err;
    if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    BIO_push(bdec, bmem2);

    total_dt = BIO_read(bdec, decrypted, sizeof(decrypted));
    if (!TEST_int_gt(total_dt, 0))
        goto err;

    if (!TEST_true(BIO_get_cipher_status(bdec)))
        goto err;

    if (!TEST_mem_eq(decrypted, total_dt, plaintext, sizeof(plaintext)))
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
