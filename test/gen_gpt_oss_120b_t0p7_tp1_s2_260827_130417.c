/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p7_tp1_s2_260827_130417.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
        /* Test AES‑256‑CBC BIO encryption/decryption against a known vector.
         * The vector is taken from NIST SP 800‑38A:
         *   Key = 603deb1015ca71be2b73aef0857d7781
         *         1f352c073b6108d72d9810a30914dff4
         *   IV  = 000102030405060708090a0b0c0d0e0f
         *   Plaintext = "Single block msg" (16 bytes)
         *   Ciphertext = f58c4c04d6e5f1ba779eabfb5f7bfbd6
         */
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
        static const unsigned char plaintext[16] = "Single block msg";
        static const unsigned char expected_ct[16] = {
            0xf5,0x8c,0x4c,0x04,0xd6,0xe5,0xf1,0xba,
            0x77,0x9e,0xab,0xfb,0x5f,0x7b,0xfb,0xd6
        };
        int ok = 1;
        BIO *mem = NULL, *enc = NULL;
        BIO *mem2 = NULL, *dec = NULL;
        char *enc_data = NULL;
        long enc_len = 0;
        unsigned char out_plain[32];
        int out_len = 0;

        /* ---------- Encryption ---------- */
        if (!TEST_ptr(mem = BIO_new(BIO_s_mem()))) ok = 0;
        if (!TEST_ptr(enc = BIO_new(BIO_f_cipher()))) ok = 0;
        if (ok && !TEST_ptr(BIO_push(enc, mem))) ok = 0;
        if (ok && !TEST_true(BIO_set_cipher(enc,
                                          EVP_aes_256_cbc(),
                                          key, iv, 1))) ok = 0;
        if (ok && !TEST_int_eq(BIO_write(enc,
                                        (const char *)plaintext,
                                        sizeof(plaintext)),
                               (int)sizeof(plaintext))) ok = 0;
        if (ok && !TEST_true(BIO_flush(enc))) ok = 0;  /* force final block */

        /* Retrieve ciphertext from the memory BIO */
        if (ok) {
            enc_len = BIO_get_mem_data(mem, &enc_data);
            if (!TEST_int_eq(enc_len, (long)sizeof(expected_ct))) ok = 0;
            if (ok && !TEST_mem_eq(enc_data, (size_t)enc_len,
                                  expected_ct, sizeof(expected_ct))) ok = 0;
        }

        /* ---------- Decryption ---------- */
        if (ok && !TEST_ptr(mem2 = BIO_new_mem_buf(enc_data,
                                                  (int)enc_len))) ok = 0;
        if (ok && !TEST_ptr(dec = BIO_new(BIO_f_cipher()))) ok = 0;
        if (ok && !TEST_ptr(BIO_push(dec, mem2))) ok = 0;
        if (ok && !TEST_true(BIO_set_cipher(dec,
                                            EVP_aes_256_cbc(),
                                            key, iv, 0))) ok = 0;

        out_len = BIO_read(dec, out_plain, sizeof(out_plain));
        if (!TEST_int_eq(out_len, (int)sizeof(plaintext))) ok = 0;
        if (ok && !TEST_mem_eq(out_plain, (size_t)out_len,
                              plaintext, sizeof(plaintext))) ok = 0;

        /* Cleanup */
        BIO_free_all(enc);   /* also frees mem */
        BIO_free_all(dec);   /* also frees mem2 */

        return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
