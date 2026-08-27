/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p3_tp1_s3_260827_124746.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
        const unsigned char key[32] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
            0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
        };
        const unsigned char iv[16] = {
            0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,
            0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf
        };
        const char plaintext[] = "OpenSSL BIO cipher round‑trip test data";
        const size_t pt_len = sizeof(plaintext) - 1; /* exclude NUL */

        /* ---------- Encryption ---------- */
        BIO *mem_enc = BIO_new(BIO_s_mem());
        if (!TEST_ptr(mem_enc))
            return 0;

        BIO *cipher_enc = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(cipher_enc)) {
            BIO_free(mem_enc);
            return 0;
        }

        if (!TEST_true(BIO_set_cipher(cipher_enc,
                                      EVP_aes_256_cbc(),
                                      key, iv, 1))) {
            BIO_free_all(cipher_enc);
            BIO_free(mem_enc);
            return 0;
        }

        BIO_push(cipher_enc, mem_enc);

        if (!TEST_int_eq(BIO_write(cipher_enc, plaintext, (int)pt_len), (int)pt_len)) {
            BIO_free_all(cipher_enc);
            return 0;
        }

        if (!TEST_int_eq(BIO_flush(cipher_enc), 1)) {
            BIO_free_all(cipher_enc);
            return 0;
        }

        /* Retrieve encrypted bytes */
        char *enc_ptr = NULL;
        long enc_len = BIO_get_mem_data(mem_enc, &enc_ptr);
        if (!TEST_int_gt(enc_len, 0))
            return 0;

        unsigned char *enc_buf = OPENSSL_malloc((size_t)enc_len);
        if (!TEST_ptr(enc_buf)) {
            BIO_free_all(cipher_enc);
            return 0;
        }
        memcpy(enc_buf, enc_ptr, (size_t)enc_len);

        /* Clean up encryption chain (mem_enc is freed as part of cipher_enc) */
        BIO_free_all(cipher_enc);

        /* ---------- Decryption ---------- */
        BIO *mem_dec = BIO_new_mem_buf(enc_buf, (int)enc_len);
        if (!TEST_ptr(mem_dec)) {
            OPENSSL_free(enc_buf);
            return 0;
        }

        BIO *cipher_dec = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(cipher_dec)) {
            BIO_free(mem_dec);
            OPENSSL_free(enc_buf);
            return 0;
        }

        if (!TEST_true(BIO_set_cipher(cipher_dec,
                                      EVP_aes_256_cbc(),
                                      key, iv, 0))) {
            BIO_free_all(cipher_dec);
            BIO_free(mem_dec);
            OPENSSL_free(enc_buf);
            return 0;
        }

        BIO_push(cipher_dec, mem_dec);

        unsigned char outbuf[256];
        int outlen = BIO_read(cipher_dec, outbuf, sizeof(outbuf));
        if (!TEST_int_gt(outlen, 0)) {
            BIO_free_all(cipher_dec);
            OPENSSL_free(enc_buf);
            return 0;
        }

        if (!TEST_mem_eq(outbuf, outlen, plaintext, pt_len)) {
            BIO_free_all(cipher_dec);
            OPENSSL_free(enc_buf);
            return 0;
        }

        /* Ensure no extra data remains */
        int extra = BIO_read(cipher_dec, outbuf, sizeof(outbuf));
        TEST_int_eq(extra, 0);

        BIO_free_all(cipher_dec);
        OPENSSL_free(enc_buf);
        return 1;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
