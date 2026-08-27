/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_sonnet_remedium_r9_260828_010654.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    static const unsigned char plaintext[] =
        "The quick brown fox jumps over the lazy dog. "
        "AES-256 CBC BIO round-trip test vector data.";
    unsigned char ciphertext[256];
    unsigned char decrypted[256];
    int clen = 0, dlen = 0, tmplen;
    BIO *benc = NULL, *bmem = NULL, *bdec = NULL;
    int ret = 0;
    int plen = (int)sizeof(plaintext) - 1;

    /* Encrypt: BIO_f_cipher pushed on top of a memory BIO */
    if (!TEST_ptr(bmem = BIO_new(BIO_s_mem())))
        goto end;
    if (!TEST_ptr(benc = BIO_new(BIO_f_cipher())))
        goto end;
    if (!TEST_ptr(BIO_push(benc, bmem)))
        goto end;
    if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(), key, iv, 1)))
        goto end;

    if (!TEST_int_eq(BIO_write(benc, plaintext, plen), plen))
        goto end;
    if (!TEST_int_gt(BIO_flush(benc), 0))
        goto end;

    clen = BIO_read(bmem, ciphertext, sizeof(ciphertext));
    if (!TEST_int_gt(clen, 0))
        goto end;

    /* Ciphertext should differ from plaintext */
    if (!TEST_true(clen != plen || memcmp(ciphertext, plaintext, plen) != 0))
        goto end;

    BIO_free(benc);
    benc = NULL;
    BIO_free(bmem);
    bmem = NULL;

    /* Decrypt: feed ciphertext into a fresh memory BIO, read through cipher BIO */
    if (!TEST_ptr(bmem = BIO_new_mem_buf(ciphertext, clen)))
        goto end;
    if (!TEST_ptr(bdec = BIO_new(BIO_f_cipher())))
        goto end;
    if (!TEST_ptr(BIO_push(bdec, bmem)))
        goto end;
    if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(), key, iv, 0)))
        goto end;

    dlen = BIO_read(bdec, decrypted, sizeof(decrypted));
    if (!TEST_int_eq(dlen, plen))
        goto end;

    tmplen = BIO_read(bdec, decrypted + dlen, sizeof(decrypted) - dlen);
    if (tmplen > 0)
        dlen += tmplen;

    if (!TEST_mem_eq(decrypted, dlen, plaintext, plen))
        goto end;

    if (!TEST_int_eq(BIO_get_cipher_status(bdec), 1))
        goto end;

    ret = 1;
end:
    BIO_free(bdec);
    BIO_free(benc);
    BIO_free(bmem);
    return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
