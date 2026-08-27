/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p4_tp1_s9_260827_125412.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
        int ret = 1;
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
        const unsigned char plaintext[] = "Single block msg";
        const unsigned char expected_ct[16] = {
            0xf5,0x8c,0x4c,0x04,0xd6,0xe5,0xf1,0xba,
            0x77,0x9e,0xab,0xfb,0x5f,0x7b,0xfb,0xd6
        };
        size_t pt_len = sizeof(plaintext) - 1; /* exclude NUL */

        /* ---------- Encryption ---------- */
        BIO *mem = BIO_new(BIO_s_mem());
        BIO *enc = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(mem) || !TEST_ptr(enc))
            return 0;

        BIO_push(enc, mem);
        if (!TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                    key, iv, 1))) {
            ret = 0;
            goto cleanup_enc;
        }

        if (!TEST_int_eq(BIO_write(enc, plaintext, (int)pt_len), (int)pt_len)) {
            ret = 0;
            goto cleanup_enc;
        }
        if (!TEST_true(BIO_flush(enc))) {
            ret = 0;
            goto cleanup_enc;
        }

        /* Retrieve ciphertext from the memory BIO */
        char *enc_data = NULL;
        long enc_len = BIO_get_mem_data(mem, &enc_data);
        if (!TEST_int_eq((int)enc_len, (int)sizeof(expected_ct))) {
            ret = 0;
            goto cleanup_enc;
        }
        if (!TEST_mem_eq(enc_data, (size_t)enc_len,
                         expected_ct, sizeof(expected_ct))) {
            ret = 0;
            goto cleanup_enc;
        }

        /* ---------- Decryption ---------- */
        {
            BIO *src = BIO_new_mem_buf(enc_data, (int)enc_len);
            BIO *dec = BIO_new(BIO_f_cipher());
            if (!TEST_ptr(src) || !TEST_ptr(dec)) {
                ret = 0;
                BIO_free_all(src);
                BIO_free_all(dec);
                goto cleanup_enc;
            }

            BIO_push(dec, src);
            if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                        key, iv, 0))) {
                ret = 0;
                BIO_free_all(dec);
                goto cleanup_enc;
            }

            unsigned char outbuf[64];
            int outlen = BIO_read(dec, outbuf, sizeof(outbuf));
            if (!TEST_int_eq(outlen, (int)pt_len)) {
                ret = 0;
                BIO_free_all(dec);
                goto cleanup_enc;
            }
            if (!TEST_mem_eq(outbuf, (size_t)outlen,
                             plaintext, pt_len)) {
                ret = 0;
                BIO_free_all(dec);
                goto cleanup_enc;
            }
            BIO_free_all(dec);
        }

    cleanup_enc:
        BIO_free_all(enc); /* also frees mem */
        return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
