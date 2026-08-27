/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_sonnet_relow_r7_260828_010344.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
        "Pack my box with five dozen liquor jugs.";
    unsigned char ciphertext[256];
    unsigned char decrypted[256];
    int enc_written = 0, enc_final = 0;
    int dec_written = 0, dec_final = 0;
    int n;
    BIO *benc = NULL, *bmem = NULL, *bdec = NULL, *bmem2 = NULL;
    int ret = 0;

    /* Encrypt path: BIO_f_cipher() chained to a memory BIO */
    if (!TEST_ptr(bmem = BIO_new(BIO_s_mem())))
        goto err;
    if (!TEST_ptr(benc = BIO_new(BIO_f_cipher())))
        goto err;
    if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;
    BIO_push(benc, bmem);

    n = BIO_write(benc, plaintext, sizeof(plaintext));
    if (!TEST_int_eq(n, (int)sizeof(plaintext)))
        goto err;
    enc_written = n;

    if (!TEST_int_gt(BIO_flush(benc), 0))
        goto err;

    n = BIO_read(bmem, ciphertext, sizeof(ciphertext));
    if (!TEST_int_gt(n, 0))
        goto err;
    enc_final = n;

    /* Ciphertext should differ from plaintext and be padded to block size */
    if (!TEST_int_eq(enc_final % 16, 0))
        goto err;
    if (!TEST_mem_ne(ciphertext, enc_written, plaintext, enc_written))
        goto err;

    BIO_free(benc);
    benc = NULL;
    bmem = NULL; /* freed by BIO_free(benc) via push chain */

    /* Decrypt path */
    if (!TEST_ptr(bmem2 = BIO_new_mem_buf(ciphertext, enc_final)))
        goto err;
    if (!TEST_ptr(bdec = BIO_new(BIO_f_cipher())))
        goto err;
    if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;
    BIO_push(bdec, bmem2);

    n = BIO_read(bdec, decrypted, sizeof(decrypted));
    if (!TEST_int_gt(n, 0))
        goto err;
    dec_written = n;

    /* Read again to make sure we hit EOF/finalization cleanly */
    dec_final = BIO_read(bdec, decrypted + dec_written,
                          sizeof(decrypted) - dec_written);
    if (dec_final > 0)
        dec_written += dec_final;

    if (!TEST_int_eq(dec_written, (int)sizeof(plaintext)))
        goto err;
    if (!TEST_mem_eq(decrypted, dec_written, plaintext, sizeof(plaintext)))
        goto err;

    if (!TEST_int_eq(BIO_get_cipher_status(bdec), 1))
        goto err;

    ret = 1;

err:
    BIO_free(bdec);
    BIO_free(benc);
    if (bmem != NULL && benc == NULL)
        BIO_free(bmem);
    return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
