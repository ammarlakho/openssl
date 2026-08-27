/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t1p4_tp1_s1_260827_132339.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
        int ok = 1;
        unsigned char key[32] = {0};
        unsigned char iv[16] = {0};
        const char *plaintext = "The quick brown fox jumps over the lazy dog";
        size_t plen = strlen(plaintext);
        unsigned char expected[128];
        int expected_len = 0;

        /* Compute expected ciphertext using EVP directly */
        EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();
        if (!TEST_ptr(cctx))
            return 0;
        if (!EVP_EncryptInit_ex(cctx, EVP_aes_256_cbc(), NULL, key, iv))
            ok = 0;
        if (ok) {
            int outlen = 0;
            if (!EVP_EncryptUpdate(cctx, expected, &outlen,
                                  (const unsigned char *)plaintext,
                                  (int)plen))
                ok = 0;
            else
                expected_len = outlen;
        }
        if (ok) {
            int outlen = 0;
            if (!EVP_EncryptFinal_ex(cctx, expected + expected_len,
                                     &outlen))
                ok = 0;
            else
                expected_len += outlen;
        }
        EVP_CIPHER_CTX_free(cctx);
        if (!ok)
            return 0;

        /* Encrypt via BIO_f_cipher and compare with expected ciphertext */
        BIO *mem = BIO_new(BIO_s_mem());
        BIO *enc = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(mem) || !TEST_ptr(enc))
            return 0;
        if (!TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                     key, iv, 1)))
            ok = 0;
        if (ok)
            BIO_push(enc, mem);
        if (ok) {
            int written = BIO_write(enc, plaintext, (int)plen);
            if (!TEST_int_eq(written, (int)plen))
                ok = 0;
        }
        if (ok && !TEST_true(BIO_flush(enc)))
            ok = 0;

        char *enc_data = NULL;
        long enc_len = 0;
        if (ok) {
            enc_len = BIO_get_mem_data(mem, &enc_data);
            if (!TEST_long_eq(enc_len, expected_len))
                ok = 0;
            if (!TEST_mem_eq(enc_data, (size_t)enc_len,
                             expected, (size_t)expected_len))
                ok = 0;
        }

        /* Decrypt the ciphertext using BIO_f_cipher and compare with original */
        BIO *mem2 = NULL;
        BIO *dec = NULL;
        if (ok) {
            mem2 = BIO_new_mem_buf(enc_data, (int)enc_len);
            dec = BIO_new(BIO_f_cipher());
            if (!TEST_ptr(mem2) || !TEST_ptr(dec))
                ok = 0;
        }
        if (ok) {
            if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                         key, iv, 0)))
                ok = 0;
        }
        if (ok)
            BIO_push(dec, mem2);

        unsigned char outbuf[128];
        int total = 0;
        if (ok) {
            while (total < (int)plen) {
                int r = BIO_read(dec, outbuf + total,
                                 sizeof(outbuf) - total);
                if (r <= 0)
                    break;
                total += r;
            }
            if (!TEST_int_eq(total, (int)plen))
                ok = 0;
            if (!TEST_mem_eq(outbuf, (size_t)total,
                             plaintext, plen))
                ok = 0;
        }

        BIO_free_all(enc);
        BIO_free_all(dec);
        return ok ? 1 : 0;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
