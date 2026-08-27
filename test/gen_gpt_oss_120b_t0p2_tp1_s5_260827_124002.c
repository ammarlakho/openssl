/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p2_tp1_s5_260827_124002.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
        const unsigned char key[32] = {0};
        const unsigned char iv[16] = {0};
        const char plaintext[] = "OpenSSL BIO cipher round‑trip test data";
        const size_t pt_len = sizeof(plaintext) - 1; /* omit terminating NUL */

        /* ---------- encrypt ---------- */
        BIO *src = BIO_new_mem_buf(plaintext, (int)pt_len);
        if (!TEST_ptr(src))
            return 0;

        BIO *enc = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(enc))
            return 0;
        if (!TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                      key, iv, 1)))
            return 0;

        /* enc reads from src */
        BIO_push(enc, src);

        unsigned char enc_buf[pt_len + EVP_MAX_BLOCK_LENGTH];
        int enc_len = 0;

        for (;;) {
            int r = BIO_read(enc, enc_buf + enc_len,
                             (int)sizeof(enc_buf) - enc_len);
            if (r > 0) {
                enc_len += r;
                continue;
            }
            if (r == 0)
                break;
            if (!BIO_should_retry(enc)) {
                TEST_true(0);
                break;
            }
        }

        if (!TEST_int_gt(enc_len, 0))
            return 0;

        /* ---------- decrypt ---------- */
        BIO *csrc = BIO_new_mem_buf(enc_buf, enc_len);
        if (!TEST_ptr(csrc))
            return 0;

        BIO *dec = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(dec))
            return 0;
        if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                      key, iv, 0)))
            return 0;

        BIO_push(dec, csrc);

        unsigned char dec_buf[pt_len];
        int dec_len = 0;

        for (;;) {
            int r = BIO_read(dec, dec_buf + dec_len,
                             (int)sizeof(dec_buf) - dec_len);
            if (r > 0) {
                dec_len += r;
                continue;
            }
            if (r == 0)
                break;
            if (!BIO_should_retry(dec)) {
                TEST_true(0);
                break;
            }
        }

        /* Verify that decryption reproduces the original plaintext */
        if (!TEST_int_eq(dec_len, (int)pt_len))
            return 0;
        if (!TEST_mem_eq(dec_buf, dec_len, plaintext, pt_len))
            return 0;

        /* Clean up */
        BIO_free_all(enc);
        BIO_free_all(dec);

        return 1;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
