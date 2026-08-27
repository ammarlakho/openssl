/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_sonnet_relow_r8_260828_010357.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
        "AES-256 CBC round trip test vector data.";
    const int ptlen = (int)strlen((const char *)plaintext);

    BIO *benc = NULL, *bmem = NULL, *bdec = NULL, *bmemdec = NULL;
    unsigned char ciphertext[1024];
    unsigned char decrypted[1024];
    int enc_written = 0, n, total = 0;
    int ok = 0;

    /* Encrypt: write plaintext through BIO_f_cipher into a memory BIO */
    if (!TEST_ptr(bmem = BIO_new(BIO_s_mem())))
        goto err;
    if (!TEST_ptr(benc = BIO_new(BIO_f_cipher())))
        goto err;
    if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;
    BIO_push(benc, bmem);

    if (!TEST_int_gt(BIO_write(benc, plaintext, ptlen), 0))
        goto err;
    if (!TEST_int_ge(BIO_flush(benc), 0))
        goto err;
    if (!TEST_true(BIO_get_cipher_status(benc)))
        goto err;

    enc_written = BIO_read(bmem, ciphertext, sizeof(ciphertext));
    if (!TEST_int_gt(enc_written, 0))
        goto err;

    /* Ciphertext should not equal plaintext (sanity) and length should be
     * a multiple of block size (16) due to CBC padding */
    if (!TEST_int_eq(enc_written % 16, 0))
        goto err;

    BIO_free(benc);
    benc = NULL;
    /* bmem was freed as part of push chain via BIO_free_all normally,
     * but we already drained it; free explicitly now */
    BIO_free(bmem);
    bmem = NULL;

    /* Decrypt: feed ciphertext through a mem BIO -> BIO_f_cipher */
    if (!TEST_ptr(bmemdec = BIO_new_mem_buf(ciphertext, enc_written)))
        goto err;
    if (!TEST_ptr(bdec = BIO_new(BIO_f_cipher())))
        goto err;
    if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;
    BIO_push(bdec, bmemdec);

    total = 0;
    while ((n = BIO_read(bdec, decrypted + total,
                          (int)sizeof(decrypted) - total)) > 0) {
        total += n;
        if (total >= (int)sizeof(decrypted))
            break;
    }

    if (!TEST_true(BIO_get_cipher_status(bdec)))
        goto err;
    if (!TEST_int_eq(total, ptlen))
        goto err;
    if (!TEST_mem_eq(decrypted, total, plaintext, ptlen))
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
