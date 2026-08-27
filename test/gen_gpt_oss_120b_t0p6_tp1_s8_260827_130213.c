/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p6_tp1_s8_260827_130213.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    int ok = 1;
    /* AES‑256‑CBC test vector (RFC 3602) */
    const unsigned char key[32] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
        0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };
    const unsigned char iv[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    const unsigned char plaintext[16] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
    };
    const unsigned char expected_ct[16] = {
        0xf5,0x8c,0x4c,0x04,0xd6,0xe5,0xf1,0xba,
        0x77,0x9e,0xab,0xfb,0x5f,0x7b,0xfb,0xd6
    };

    BIO *mem = NULL, *cipher = NULL;
    long enc_len = 0;
    const char *enc_ptr = NULL;
    unsigned char outbuf[64];
    int outlen = 0;

    /* ---------- Encryption ---------- */
    mem = BIO_new(BIO_s_mem());
    if (!TEST_ptr(mem))
        return 0;

    cipher = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(cipher)) {
        BIO_free(mem);
        return 0;
    }

    if (!TEST_true(BIO_set_cipher(cipher, EVP_aes_256_cbc(),
                                 key, iv, 1))) {
        BIO_free_all(cipher);
        BIO_free(mem);
        return 0;
    }

    BIO_push(cipher, mem);

    if (!TEST_int_eq(BIO_write(cipher, plaintext, sizeof(plaintext)),
                     (int)sizeof(plaintext))) {
        ok = 0;
    }

    if (!TEST_true(BIO_flush(cipher))) {
        ok = 0;
    }

    enc_len = BIO_get_mem_data(mem, &enc_ptr);
    if (!TEST_int_eq((int)enc_len, (int)sizeof(expected_ct)))
        ok = 0;
    if (!TEST_mem_eq(enc_ptr, (size_t)enc_len,
                     expected_ct, sizeof(expected_ct)))
        ok = 0;

    BIO_free_all(cipher); /* also frees mem */

    /* ---------- Decryption ---------- */
    {
        BIO *mem2 = BIO_new_mem_buf(enc_ptr, (int)enc_len);
        BIO *dec  = BIO_new(BIO_f_cipher());

        if (!TEST_ptr(mem2) || !TEST_ptr(dec)) {
            BIO_free_all(mem2);
            BIO_free_all(dec);
            return 0;
        }

        if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                      key, iv, 0))) {
            BIO_free_all(dec);
            BIO_free_all(mem2);
            return 0;
        }

        BIO_push(dec, mem2);

        outlen = BIO_read(dec, outbuf, sizeof(outbuf));
        if (!TEST_int_eq(outlen, (int)sizeof(plaintext)))
            ok = 0;
        if (!TEST_mem_eq(outbuf, (size_t)outlen,
                         plaintext, sizeof(plaintext)))
            ok = 0;

        BIO_free_all(dec); /* also frees mem2 */
    }

    return ok;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
