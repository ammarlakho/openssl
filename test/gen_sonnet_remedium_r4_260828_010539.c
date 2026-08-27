/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_sonnet_remedium_r4_260828_010539.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
        0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00
    };
    static const unsigned char plaintext[] =
        "The quick brown fox jumps over the lazy dog. "
        "Pack my box with five dozen liquor jugs.";
    const int plen = (int)(sizeof(plaintext) - 1);
    unsigned char enc_out[256];
    unsigned char dec_out[256];
    int enc_len = 0, tmplen = 0, dec_len = 0;
    int ret = 0;
    BIO *benc = NULL, *bmem = NULL;
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    int i;

    /* Encrypt using BIO_f_cipher chained over a memory BIO */
    if (!TEST_ptr(bmem = BIO_new(BIO_s_mem())))
        goto err;
    if (!TEST_ptr(benc = BIO_new(BIO_f_cipher())))
        goto err;
    if (!TEST_ptr(BIO_push(benc, bmem)))
        goto err;
    if (!TEST_true(BIO_set_cipher(benc, cipher, key, iv, 1 /* encrypt */)))
        goto err;

    if (!TEST_int_eq(BIO_write(benc, plaintext, plen), plen))
        goto err;
    if (!TEST_int_gt(BIO_flush(benc), 0))
        goto err;
    if (!TEST_true(BIO_get_cipher_status(benc)))
        goto err;

    enc_len = BIO_read(bmem, enc_out, sizeof(enc_out));
    if (!TEST_int_gt(enc_len, 0))
        goto err;

    /*
     * With AES-256-CBC (block size 16), the ciphertext length must be a
     * multiple of the block size and strictly greater than the plaintext
     * length due to PKCS#7 padding.
     */
    if (!TEST_int_gt(enc_len, plen))
        goto err;
    if (!TEST_int_eq(enc_len % 16, 0))
        goto err;

    BIO_free(benc);
    benc = NULL;
    BIO_free(bmem);
    bmem = NULL;

    /* Now decrypt independently and verify round-trip equals original */
    if (!TEST_ptr(bmem = BIO_new(BIO_s_mem())))
        goto err;
    if (!TEST_int_eq(BIO_write(bmem, enc_out, enc_len), enc_len))
        goto err;

    if (!TEST_ptr(benc = BIO_new(BIO_f_cipher())))
        goto err;
    if (!TEST_ptr(BIO_push(benc, bmem)))
        goto err;
    if (!TEST_true(BIO_set_cipher(benc, cipher, key, iv, 0 /* decrypt */)))
        goto err;

    dec_len = BIO_read(benc, dec_out, sizeof(dec_out));
    if (!TEST_int_eq(dec_len, plen))
        goto err;
    if (!TEST_true(BIO_get_cipher_status(benc)))
        goto err;
    if (!TEST_mem_eq(dec_out, dec_len, plaintext, plen))
        goto err;

    /* Sanity: decrypting a corrupted ciphertext should not silently succeed */
    BIO_free(benc);
    benc = NULL;
    BIO_free(bmem);
    bmem = NULL;

    if (enc_len > 0) {
        unsigned char corrupted[256];

        memcpy(corrupted, enc_out, enc_len);
        for (i = 0; i < enc_len; i++)
            corrupted[i] ^= 0xff;

        if (!TEST_ptr(bmem = BIO_new(BIO_s_mem())))
            goto err;
        if (!TEST_int_eq(BIO_write(bmem, corrupted, enc_len), enc_len))
            goto err;
        if (!TEST_ptr(benc = BIO_new(BIO_f_cipher())))
            goto err;
        if (!TEST_ptr(BIO_push(benc, bmem)))
            goto err;
        if (!TEST_true(BIO_set_cipher(benc, cipher, key, iv, 0)))
            goto err;

        dec_len = BIO_read(benc, dec_out, sizeof(dec_out));
        /*
         * Either the read fails outright, or the cipher status reports
         * failure (bad padding), or the decrypted data differs from the
         * original plaintext. All are acceptable failure indications.
         */
        if (dec_len == plen
            && BIO_get_cipher_status(benc)
            && memcmp(dec_out, plaintext, plen) == 0) {
            TEST_error("corrupted ciphertext unexpectedly decrypted correctly");
            goto err;
        }
    }

    ret = 1;
err:
    BIO_free(benc);
    BIO_free(bmem);
    return ret;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
