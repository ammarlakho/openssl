/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_sonnet_rehigh_r1_260828_010734.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
        0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18,
        0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10
    };
    static const unsigned char pt[] =
        "The quick brown fox jumps over the lazy dog. "
        "OpenSSL AES-256 CBC BIO round-trip test vector, "
        "with some extra padding bytes to exceed one block.";
    const int ptlen = (int)(sizeof(pt) - 1); /* exclude trailing NUL */

    int ok = 0;
    BIO *bmem = NULL, *benc = NULL;
    BIO *bmem2 = NULL, *bdec = NULL;
    EVP_CIPHER_CTX *ectx = NULL;
    unsigned char *ct_expected = NULL;
    unsigned char *dec_buf = NULL;
    int ct_exp_len = 0, outl = 0, tmplen = 0;
    unsigned char *mem_ct = NULL;
    long mem_ct_len = 0;
    int dec_len = 0, r;

    /* Compute the expected ciphertext directly via EVP for comparison. */
    if (!TEST_ptr(ectx = EVP_CIPHER_CTX_new()))
        goto err;
    if (!TEST_true(EVP_EncryptInit_ex(ectx, EVP_aes_256_cbc(), NULL, key, iv)))
        goto err;
    if (!TEST_ptr(ct_expected = OPENSSL_malloc(ptlen + EVP_MAX_BLOCK_LENGTH)))
        goto err;
    if (!TEST_true(EVP_EncryptUpdate(ectx, ct_expected, &outl, pt, ptlen)))
        goto err;
    ct_exp_len = outl;
    if (!TEST_true(EVP_EncryptFinal_ex(ectx, ct_expected + ct_exp_len, &tmplen)))
        goto err;
    ct_exp_len += tmplen;
    EVP_CIPHER_CTX_free(ectx);
    ectx = NULL;

    /* Encrypt via a BIO_f_cipher() filter layered over a memory BIO. */
    if (!TEST_ptr(bmem = BIO_new(BIO_s_mem())))
        goto err;
    if (!TEST_ptr(benc = BIO_new(BIO_f_cipher()))) {
        BIO_free(bmem);
        goto err;
    }
    BIO_push(benc, bmem);

    if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (!TEST_int_eq(BIO_write(benc, pt, ptlen), ptlen))
        goto err;

    if (!TEST_int_eq((int)BIO_flush(benc), 1))
        goto err;

    if (!TEST_long_eq(BIO_get_cipher_status(benc), 1))
        goto err;

    mem_ct_len = BIO_get_mem_data(bmem, &mem_ct);
    if (!TEST_int_eq((int)mem_ct_len, ct_exp_len))
        goto err;
    if (!TEST_mem_eq(mem_ct, (size_t)mem_ct_len,
                      ct_expected, (size_t)ct_exp_len))
        goto err;

    /* Decrypt the fixed ciphertext back via a fresh BIO_f_cipher() chain. */
    if (!TEST_ptr(bmem2 = BIO_new_mem_buf(ct_expected, ct_exp_len)))
        goto err;
    if (!TEST_ptr(bdec = BIO_new(BIO_f_cipher()))) {
        BIO_free(bmem2);
        goto err;
    }
    BIO_push(bdec, bmem2);

    if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    if (!TEST_ptr(dec_buf = OPENSSL_malloc(ptlen + EVP_MAX_BLOCK_LENGTH)))
        goto err;

    dec_len = 0;
    for (;;) {
        r = BIO_read(bdec, dec_buf + dec_len,
                      ptlen + EVP_MAX_BLOCK_LENGTH - dec_len);
        if (r <= 0)
            break;
        dec_len += r;
    }

    if (!TEST_long_eq(BIO_get_cipher_status(bdec), 1))
        goto err;

    if (!TEST_int_eq(dec_len, ptlen))
        goto err;
    if (!TEST_mem_eq(dec_buf, (size_t)dec_len, pt, (size_t)ptlen))
        goto err;

    ok = 1;

 err:
    OPENSSL_free(ct_expected);
    OPENSSL_free(dec_buf);
    EVP_CIPHER_CTX_free(ectx);
    BIO_free_all(benc);
    BIO_free_all(bdec);
    return ok;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
