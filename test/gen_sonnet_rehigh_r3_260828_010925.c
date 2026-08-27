/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_sonnet_rehigh_r3_260828_010925.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
{
    static const unsigned char key[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x11, 0xf3, 0x52, 0xc0, 0x73, 0xb6, 0x10, 0x8d,
        0x72, 0xd9, 0x81, 0x0a, 0x30, 0x91, 0x4d, 0xff
    };
    static const unsigned char iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    static const unsigned char plaintext[16] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };
    static const unsigned char expected_ct[16] = {
        0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba,
        0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6
    };
    static const unsigned char msg[] =
        "The quick brown fox jumps over the lazy dog, 12345!";
    int ok = 0;
    BIO *benc = NULL, *bmem = NULL;
    BIO *bdec = NULL, *bmem2 = NULL;
    BIO *benc3 = NULL, *bmem3 = NULL;
    BIO *bdec2 = NULL, *bmem4 = NULL;
    EVP_CIPHER_CTX *cctx = NULL;
    char *mem_data = NULL;
    long mem_len = 0;
    unsigned char outbuf[64];
    int outlen;
    unsigned char *ciphertext_rt = NULL;
    int ciphertext_rt_len = 0;
    unsigned char decbuf[128];
    int declen;

    /* --- Part 1: encrypt a single fixed block, no padding, compare to
     * a known AES-256-CBC test vector. --- */
    if (!TEST_ptr(benc = BIO_new(BIO_f_cipher())))
        goto err;
    if (!TEST_ptr(bmem = BIO_new(BIO_s_mem())))
        goto err;
    if (!TEST_ptr(BIO_push(benc, bmem)))
        goto err;

    if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (!TEST_int_gt(BIO_get_cipher_ctx(benc, &cctx), 0) || !TEST_ptr(cctx))
        goto err;
    if (!TEST_true(EVP_CIPHER_CTX_set_padding(cctx, 0)))
        goto err;

    if (!TEST_int_eq(BIO_write(benc, plaintext, sizeof(plaintext)),
                      (int)sizeof(plaintext)))
        goto err;
    if (!TEST_int_gt(BIO_flush(benc), 0))
        goto err;

    mem_len = BIO_get_mem_data(bmem, &mem_data);
    if (!TEST_int_eq((int)mem_len, (int)sizeof(expected_ct)))
        goto err;
    if (!TEST_mem_eq(mem_data, (int)mem_len,
                      expected_ct, (int)sizeof(expected_ct)))
        goto err;

    /* --- Part 2: decrypt the ciphertext just produced and confirm we
     * recover the original plaintext exactly. --- */
    if (!TEST_ptr(bmem2 = BIO_new_mem_buf(mem_data, (int)mem_len)))
        goto err;
    if (!TEST_ptr(bdec = BIO_new(BIO_f_cipher())))
        goto err;
    if (!TEST_ptr(BIO_push(bdec, bmem2)))
        goto err;

    if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    cctx = NULL;
    if (!TEST_int_gt(BIO_get_cipher_ctx(bdec, &cctx), 0) || !TEST_ptr(cctx))
        goto err;
    if (!TEST_true(EVP_CIPHER_CTX_set_padding(cctx, 0)))
        goto err;

    memset(outbuf, 0, sizeof(outbuf));
    outlen = BIO_read(bdec, outbuf, sizeof(outbuf));
    if (!TEST_int_eq(outlen, (int)sizeof(plaintext)))
        goto err;
    if (!TEST_mem_eq(outbuf, outlen, plaintext, (int)sizeof(plaintext)))
        goto err;

    /* --- Part 3: general round-trip with default padding on an
     * arbitrary-length message not aligned to the block size. --- */
    if (!TEST_ptr(benc3 = BIO_new(BIO_f_cipher())))
        goto err;
    if (!TEST_ptr(bmem3 = BIO_new(BIO_s_mem())))
        goto err;
    if (!TEST_ptr(BIO_push(benc3, bmem3)))
        goto err;

    if (!TEST_true(BIO_set_cipher(benc3, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (!TEST_int_eq(BIO_write(benc3, msg, (int)(sizeof(msg) - 1)),
                      (int)(sizeof(msg) - 1)))
        goto err;
    if (!TEST_int_gt(BIO_flush(benc3), 0))
        goto err;

    mem_len = BIO_get_mem_data(bmem3, &mem_data);
    if (!TEST_int_gt((int)mem_len, 0))
        goto err;
    /* padded ciphertext must be strictly longer than the plaintext */
    if (!TEST_int_gt((int)mem_len, (int)(sizeof(msg) - 1)))
        goto err;

    ciphertext_rt_len = (int)mem_len;
    if (!TEST_ptr(ciphertext_rt = OPENSSL_malloc(ciphertext_rt_len)))
        goto err;
    memcpy(ciphertext_rt, mem_data, ciphertext_rt_len);

    if (!TEST_ptr(bmem4 = BIO_new_mem_buf(ciphertext_rt, ciphertext_rt_len)))
        goto err;
    if (!TEST_ptr(bdec2 = BIO_new(BIO_f_cipher())))
        goto err;
    if (!TEST_ptr(BIO_push(bdec2, bmem4)))
        goto err;

    if (!TEST_true(BIO_set_cipher(bdec2, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    memset(decbuf, 0, sizeof(decbuf));
    declen = BIO_read(bdec2, decbuf, sizeof(decbuf));
    if (!TEST_int_eq(declen, (int)(sizeof(msg) - 1)))
        goto err;
    if (!TEST_mem_eq(decbuf, declen, msg, (int)(sizeof(msg) - 1)))
        goto err;

    ok = 1;

err:
    BIO_free_all(benc);
    BIO_free_all(bdec);
    BIO_free_all(benc3);
    BIO_free_all(bdec2);
    OPENSSL_free(ciphertext_rt);

    return ok;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
