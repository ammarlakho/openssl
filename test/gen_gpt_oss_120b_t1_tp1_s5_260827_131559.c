/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t1_tp1_s5_260827_131559.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    /* Test data – a pattern that can be sliced to any length */
    unsigned char pattern[256];
    for (size_t i = 0; i < sizeof(pattern); i++)
        pattern[i] = (unsigned char)i;

    /* Lengths to exercise, including zero and non‑multiple of block size */
    const int test_lens[] = { 0, 1, 15, 16, 31, 32, 48, 64, 128, 255 };
    const size_t ntests = sizeof(test_lens) / sizeof(test_lens[0]);

    for (size_t ti = 0; ti < ntests; ++ti) {
        int len = test_lens[ti];
        /* -------------------- Encryption -------------------- */
        BIO *mem_enc = BIO_new(BIO_s_mem());
        BIO *b_enc   = BIO_new(BIO_f_cipher());

        if (!TEST_ptr(mem_enc) || !TEST_ptr(b_enc))
            goto err;

        if (!TEST_true(BIO_set_cipher(b_enc, EVP_aes_256_cbc(),
                                    key, iv, 1))) /* encrypt */
            goto err;

        /* Chain: b_enc -> mem_enc */
        BIO_push(b_enc, mem_enc);

        if (!TEST_int_eq(BIO_write(b_enc, pattern, len), len))
            goto err;
        if (!TEST_int_eq(BIO_flush(b_enc), 1))
            goto err;

        /* Extract ciphertext from the memory BIO */
        char *cipher_data = NULL;
        long cipher_len = BIO_get_mem_data(mem_enc, &cipher_data);
        if (!TEST_int_gt(cipher_len, 0))
            goto err;

        /* -------------------- Decryption -------------------- */
        BIO *mem_dec = BIO_new_mem_buf(cipher_data, (int)cipher_len);
        BIO *b_dec   = BIO_new(BIO_f_cipher());

        if (!TEST_ptr(mem_dec) || !TEST_ptr(b_dec))
            goto err;

        if (!TEST_true(BIO_set_cipher(b_dec, EVP_aes_256_cbc(),
                                    key, iv, 0))) /* decrypt */
            goto err;

        BIO_push(b_dec, mem_dec);

        unsigned char outbuf[256] = {0};
        int out_total = 0;
        for (;;) {
            int r = BIO_read(b_dec, outbuf + out_total,
                             (int)sizeof(outbuf) - out_total);
            if (r > 0) {
                out_total += r;
                continue;
            }
            if (r == 0)
                break;                     /* No more data */
            if (!BIO_should_retry(b_dec))
                goto err;                 /* Unexpected error */
            break;
        }
        if (!TEST_int_eq(out_total, len))
            goto err;
        if (!TEST_mem_eq(outbuf, out_total, pattern, len))
            goto err;

        /* Clean up objects for this iteration */
        BIO_free_all(b_enc);   /* also frees mem_enc */
        BIO_free_all(b_dec);   /* also frees mem_dec */
    }

    /* All iterations succeeded */
    return 1;

err:
    /* Attempt to free any allocated BIOs before returning failure */
    BIO_free_all(b_enc);
    BIO_free_all(mem_enc);
    BIO_free_all(b_dec);
    BIO_free_all(mem_dec);
    return 0;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
