/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_sonnet_relow_r10_260828_010422.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    BIO *benc = NULL, *bmem = NULL;
    EVP_CIPHER_CTX *ctx;
    const unsigned char key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    const unsigned char iv[16] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    const unsigned char plaintext[] =
        "The quick brown fox jumps over the lazy dog. "
        "This is a test message for AES-256 CBC BIO round trip.";
    unsigned char ciphertext[256];
    unsigned char decrypted[256];
    int clen = 0, dlen = 0, ret;
    int total_written = 0;

    /* Encrypt: BIO_f_cipher chained to a memory BIO */
    if (!TEST_ptr(bmem = BIO_new(BIO_s_mem())))
        return 0;
    if (!TEST_ptr(benc = BIO_new(BIO_f_cipher()))) {
        BIO_free(bmem);
        return 0;
    }
    if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(), key, iv, 1))) {
        BIO_free(bmem);
        BIO_free(benc);
        return 0;
    }
    BIO_push(benc, bmem);

    ret = BIO_write(benc, plaintext, (int)strlen((const char *)plaintext));
    if (!TEST_int_gt(ret, 0)) {
        BIO_free_all(benc);
        return 0;
    }
    total_written = ret;

    if (!TEST_int_eq(BIO_flush(benc), 1)) {
        BIO_free_all(benc);
        return 0;
    }

    clen = BIO_read(bmem, ciphertext, sizeof(ciphertext));
    if (!TEST_int_gt(clen, 0)) {
        BIO_free_all(benc);
        return 0;
    }

    /* Verify cipher context accessible via BIO_get_cipher_ctx */
    if (!TEST_ptr(ctx = NULL)
        && !TEST_true(BIO_get_cipher_ctx(benc, &ctx))) {
        BIO_free_all(benc);
        return 0;
    }

    BIO_free_all(benc);

    /* Sanity: ciphertext should differ from plaintext (not equal length-wise necessarily) */
    if (!TEST_int_ge(clen, total_written)) {
        return 0;
    }

    /* Decrypt: new BIO_f_cipher chained to a memory BIO with ciphertext */
    if (!TEST_ptr(bmem = BIO_new_mem_buf(ciphertext, clen)))
        return 0;
    if (!TEST_ptr(benc = BIO_new(BIO_f_cipher()))) {
        BIO_free(bmem);
        return 0;
    }
    if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(), key, iv, 0))) {
        BIO_free(bmem);
        BIO_free(benc);
        return 0;
    }
    BIO_push(benc, bmem);

    dlen = BIO_read(benc, decrypted, sizeof(decrypted));
    if (!TEST_int_gt(dlen, 0)) {
        BIO_free_all(benc);
        return 0;
    }

    if (!TEST_true(BIO_get_cipher_status(benc))) {
        BIO_free_all(benc);
        return 0;
    }

    BIO_free_all(benc);

    if (!TEST_int_eq(dlen, total_written)) {
        return 0;
    }

    if (!TEST_mem_eq(decrypted, dlen, plaintext, total_written)) {
        return 0;
    }

    return 1;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
