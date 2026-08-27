/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p2_tp0p95_fp0p3_s1_260827_002402.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
        int ret = 0;
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

        BIO *mem = NULL, *enc = NULL;
        char *enc_data = NULL;
        long enc_len = 0;
        unsigned char out[sizeof(plaintext)];
        int outlen = 0;
        BIO *mem_in = NULL, *dec = NULL;

        /* ---------- Encryption ---------- */
        if (!TEST_ptr(mem = BIO_new(BIO_s_mem())) ||
            !TEST_ptr(enc = BIO_new(BIO_f_cipher())) ||
            !TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                     key, iv, 1))) {
            goto end;
        }
        BIO_push(enc, mem);
        if (!TEST_int_eq(BIO_write(enc, plaintext, sizeof(plaintext)),
                         sizeof(plaintext))) {
            goto end;
        }
        if (!TEST_true(BIO_flush(enc))) {
            goto end;
        }
        enc_len = BIO_get_mem_data(mem, &enc_data);
        if (!TEST_int_eq((int)enc_len, sizeof(expected_ct)) ||
            !TEST_mem_eq(enc_data, (size_t)enc_len,
                         expected_ct, sizeof(expected_ct))) {
            goto end;
        }

        /* ---------- Decryption ---------- */
        if (!TEST_ptr(mem_in = BIO_new_mem_buf(enc_data, (int)enc_len)) ||
            !TEST_ptr(dec = BIO_new(BIO_f_cipher())) ||
            !TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                     key, iv, 0))) {
            goto end;
        }
        BIO_push(dec, mem_in);
        outlen = BIO_read(dec, out, sizeof(out));
        if (!TEST_int_eq(outlen, sizeof(plaintext)) ||
            !TEST_mem_eq(out, sizeof(out), plaintext, sizeof(plaintext))) {
            goto end;
        }

        ret = 1;
    end:
        BIO_free_all(enc);
        BIO_free_all(dec);
        return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
