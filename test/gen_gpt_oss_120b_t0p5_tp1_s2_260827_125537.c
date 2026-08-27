/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p5_tp1_s2_260827_125537.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        };
        const unsigned char iv[16] = {
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d, 0x0e, 0x0f
        };
        const unsigned char plaintext[] =
            "The quick brown fox jumps over the lazy dog";
        const int ptlen = (int)sizeof(plaintext) - 1; /* exclude NUL */

        /* ---------- Encryption ---------- */
        BIO *mem_enc = BIO_new(BIO_s_mem());
        BIO *cipher_enc = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(mem_enc) || !TEST_ptr(cipher_enc))
            return 0;

        if (!TEST_true(BIO_set_cipher(cipher_enc,
                                      EVP_aes_256_cbc(),
                                      key, iv, 1)))
            ret = 0;

        /* Chain: cipher -> mem */
        BIO_push(cipher_enc, mem_enc);

        if (!TEST_int_eq(BIO_write(cipher_enc, plaintext, ptlen), ptlen))
            ret = 0;
        if (!TEST_true(BIO_flush(cipher_enc)))
            ret = 0;

        /* Retrieve encrypted data */
        char *enc_data = NULL;
        long enc_len = BIO_get_mem_data(mem_enc, &enc_data);
        if (!TEST_int_gt(enc_len, 0))
            ret = 0;

        /* Copy encrypted data because the underlying BIO will be freed */
        unsigned char *enc_copy = OPENSSL_malloc(enc_len);
        if (!TEST_ptr(enc_copy))
            ret = 0;
        else
            memcpy(enc_copy, enc_data, enc_len);

        /* Cleanup encryption chain */
        BIO_free_all(cipher_enc); /* also frees mem_enc */

        if (!ret) {
            OPENSSL_free(enc_copy);
            return 0;
        }

        /* ---------- Decryption ---------- */
        BIO *mem_dec = BIO_new_mem_buf(enc_copy, (int)enc_len);
        BIO *cipher_dec = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(mem_dec) || !TEST_ptr(cipher_dec)) {
            OPENSSL_free(enc_copy);
            return 0;
        }

        if (!TEST_true(BIO_set_cipher(cipher_dec,
                                      EVP_aes_256_cbc(),
                                      key, iv, 0)))
            ret = 0;

        /* Chain: cipher -> mem */
        BIO_push(cipher_dec, mem_dec);

        unsigned char outbuf[256];
        int outlen = BIO_read(cipher_dec, outbuf, sizeof(outbuf));
        if (!TEST_int_gt(outlen, 0))
            ret = 0;
        if (!TEST_mem_eq(outbuf, outlen, plaintext, ptlen))
            ret = 0;

        /* Cleanup decryption chain */
        BIO_free_all(cipher_dec); /* also frees mem_dec */
        OPENSSL_free(enc_copy);

        return ret ? 1 : 0;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
