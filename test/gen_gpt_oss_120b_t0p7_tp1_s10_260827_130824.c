/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p7_tp1_s10_260827_130824.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    /* AES‑256‑CBC test vector (RFC 3602) */
    static const unsigned char key[32] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
        0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };
    static const unsigned char iv[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const unsigned char plaintext[] = "Single block msg";      /* 16 bytes */
    static const unsigned char expected_cipher[16] = {
        0xf5,0x8c,0x4c,0x04,0xd6,0xe5,0xf1,0xba,
        0x77,0x9e,0xab,0xfb,0x5f,0x7b,0xfb,0xd6
    };
    const char *cdata = NULL;
    long clen = 0;
    unsigned char cbuf[32];
    unsigned char outbuf[32];
    int outlen = 0;
    BIO *mem = NULL, *enc = NULL;
    BIO *mem2 = NULL, *dec = NULL;
    int ret = 0;

    /* ---------- Encryption ---------- */
    if (!TEST_ptr(mem = BIO_new(BIO_s_mem())))
        goto err;
    if (!TEST_ptr(enc = BIO_new(BIO_f_cipher())))
        goto err;
    if (!TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                 key, iv, 1)))          /* encrypt */
        goto err;

    BIO_push(enc, mem);

    if (!TEST_int_eq(BIO_write(enc, plaintext,
                               (int)sizeof(plaintext) - 1),
                     (int)sizeof(plaintext) - 1))
        goto err;
    if (!TEST_true(BIO_flush(enc)))
        goto err;

    clen = BIO_get_mem_data(mem, &cdata);
    if (!TEST_int_eq(clen, (long)sizeof(expected_cipher)))
        goto err;
    if (!TEST_mem_eq(cdata, (size_t)clen,
                     expected_cipher, sizeof(expected_cipher)))
        goto err;

    /* keep a copy of the ciphertext before freeing the encryption chain */
    memcpy(cbuf, cdata, (size_t)clen);

    BIO_free_all(enc);      /* also frees mem */

    /* ---------- Decryption ---------- */
    if (!TEST_ptr(mem2 = BIO_new_mem_buf(cbuf, (int)clen)))
        goto err;
    if (!TEST_ptr(dec = BIO_new(BIO_f_cipher())))
        goto err;
    if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                 key, iv, 0)))          /* decrypt */
        goto err;

    BIO_push(dec, mem2);

    outlen = BIO_read(dec, outbuf, sizeof(outbuf));
    if (!TEST_int_eq(outlen, (int)sizeof(plaintext) - 1))
        goto err;
    if (!TEST_mem_eq(outbuf, (size_t)outlen,
                     plaintext, sizeof(plaintext) - 1))
        goto err;

    ret = 1;   /* success */

err:
    BIO_free_all(dec);   /* also frees mem2 */
    return ret;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
