/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_sonnet_remedium_r7_260828_010624.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    static const unsigned char plaintext[] =
        "The quick brown fox jumps over the lazy dog. "
        "This message is intentionally not a multiple of 16 bytes.";
    const int ptlen = (int)sizeof(plaintext) - 1;
    BIO *enc_mem = NULL, *enc_chain = NULL;
    BIO *dec_mem = NULL, *dec_chain = NULL;
    unsigned char *ctdata = NULL;
    long ctlen = 0;
    unsigned char decbuf[512];
    int declen = 0, ret = 0;
    int r;

    if (!TEST_ptr(enc_mem = BIO_new(BIO_s_mem())))
        goto err;
    if (!TEST_ptr(enc_chain = BIO_new(BIO_f_cipher())))
        goto err;
    enc_chain = BIO_push(enc_chain, enc_mem);
    enc_mem = NULL;

    if (!TEST_true(BIO_set_cipher(enc_chain, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (!TEST_int_eq(BIO_write(enc_chain, plaintext, ptlen), ptlen))
        goto err;
    if (!TEST_int_ge(BIO_flush(enc_chain), 0))
        goto err;

    ctlen = BIO_get_mem_data(BIO_next(enc_chain), &ctdata);
    if (!TEST_int_gt(ctlen, 0))
        goto err;
    /* Ciphertext should not equal plaintext */
    if (ctlen == ptlen)
        TEST_mem_ne(ctdata, (size_t)ctlen, plaintext, (size_t)ptlen);

    if (!TEST_ptr(dec_mem = BIO_new_mem_buf(ctdata, (int)ctlen)))
        goto err;
    if (!TEST_ptr(dec_chain = BIO_new(BIO_f_cipher())))
        goto err;
    dec_chain = BIO_push(dec_chain, dec_mem);
    dec_mem = NULL;

    if (!TEST_true(BIO_set_cipher(dec_chain, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    r = BIO_read(dec_chain, decbuf, sizeof(decbuf));
    if (!TEST_int_eq(r, ptlen))
        goto err;
    declen = r;

    if (!TEST_mem_eq(decbuf, (size_t)declen, plaintext, (size_t)ptlen))
        goto err;

    if (!TEST_true(BIO_get_cipher_status(dec_chain)))
        goto err;

    ret = 1;
err:
    BIO_free_all(enc_chain);
    BIO_free_all(dec_chain);
    BIO_free(enc_mem);
    BIO_free(dec_mem);
    return ret;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
