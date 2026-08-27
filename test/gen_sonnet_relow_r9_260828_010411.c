/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_sonnet_relow_r9_260828_010411.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    static const unsigned char plaintext[] =
        "The quick brown fox jumps over the lazy dog. "
        "Pack my box with five dozen liquor jugs. "
        "1234567890123456789012345678901234567890";
    unsigned char ciphertext[512];
    unsigned char recovered[512];
    int clen = 0, rlen = 0, r;
    BIO *benc = NULL, *bmem = NULL, *bdec = NULL, *bmemdec = NULL;
    int ok = 0;

    /* Encrypt using BIO_f_cipher() chained onto a memory BIO */
    if (!TEST_ptr(bmem = BIO_new(BIO_s_mem())))
        goto err;
    if (!TEST_ptr(benc = BIO_new(BIO_f_cipher())))
        goto err;
    if (!TEST_ptr(BIO_push(benc, bmem)))
        goto err;
    if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (!TEST_int_eq(BIO_write(benc, plaintext, (int)strlen((const char *)plaintext)),
                      (int)strlen((const char *)plaintext)))
        goto err;
    if (!TEST_int_ge(BIO_flush(benc), 0))
        goto err;

    clen = BIO_read(bmem, ciphertext, sizeof(ciphertext));
    if (!TEST_int_gt(clen, 0))
        goto err;

    /* Ciphertext must differ from plaintext */
    if (!TEST_mem_ne(ciphertext, (size_t)clen, plaintext, strlen((const char *)plaintext)))
        goto err;

    BIO_free(benc);
    benc = NULL;
    BIO_free(bmem);
    bmem = NULL;

    /* Now decrypt back and compare to plaintext */
    if (!TEST_ptr(bmemdec = BIO_new_mem_buf(ciphertext, clen)))
        goto err;
    if (!TEST_ptr(bdec = BIO_new(BIO_f_cipher())))
        goto err;
    if (!TEST_ptr(BIO_push(bdec, bmemdec)))
        goto err;
    if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    rlen = BIO_read(bdec, recovered, sizeof(recovered));
    if (!TEST_int_gt(rlen, 0))
        goto err;

    if (!TEST_mem_eq(recovered, (size_t)rlen, plaintext, strlen((const char *)plaintext)))
        goto err;

    if (!TEST_int_eq(BIO_get_cipher_status(bdec), 1))
        goto err;

    ok = 1;

err:
    BIO_free(benc);
    BIO_free(bmem);
    BIO_free(bdec);
    BIO_free(bmemdec);
    return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
