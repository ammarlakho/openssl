/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p2_tp1_s9_260827_124147.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
        const char plaintext[] = "OpenSSL BIO cipher round‑trip test data";
        const size_t pt_len = sizeof(plaintext) - 1; /* exclude NUL */

        /* ---------- Encryption ---------- */
        BIO *mem_enc = BIO_new(BIO_s_mem());
        TEST_ptr(mem_enc);
        BIO *enc = BIO_new(BIO_f_cipher());
        TEST_ptr(enc);
        TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                               key, iv, 1)); /* encrypt */
        BIO_push(enc, mem_enc);

        /* Write the plaintext */
        TEST_int_eq(BIO_write(enc, plaintext, (int)pt_len), (int)pt_len);
        /* Flush to ensure final block is processed */
        TEST_true(BIO_flush(enc));

        /* Retrieve encrypted data from the memory BIO */
        char *enc_data = NULL;
        long enc_len = BIO_get_mem_data(mem_enc, &enc_data);
        TEST_int_gt(enc_len, 0);
        TEST_ptr(enc_data);

        /* ---------- Decryption ---------- */
        BIO *mem_dec = BIO_new_mem_buf(enc_data, (int)enc_len);
        TEST_ptr(mem_dec);
        BIO *dec = BIO_new(BIO_f_cipher());
        TEST_ptr(dec);
        TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                               key, iv, 0)); /* decrypt */
        BIO_push(dec, mem_dec);

        /* Read decrypted output */
        unsigned char outbuf[1024];
        size_t out_len = 0;
        for (;;) {
            int r = BIO_read(dec,
                            outbuf + out_len,
                            (int)(sizeof(outbuf) - out_len));
            if (r <= 0)
                break;
            out_len += (size_t)r;
            if (out_len == sizeof(outbuf))
                break;
        }

        TEST_int_eq((int)out_len, (int)pt_len);
        TEST_mem_eq(outbuf, out_len, plaintext, pt_len);

        /* Cleanup */
        BIO_free_all(enc);   /* also frees mem_enc */
        BIO_free_all(dec);   /* also frees mem_dec */

        return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
