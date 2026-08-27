/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t1_tp0p95_fp0_s3_260827_002911.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
        /* Fixed test vectors (NIST SP 800‑38A) */
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
        static const unsigned char plaintext[] = {
            0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
            0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
            0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
            0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
            0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,
            0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
            0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,
            0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10
        };
        const size_t pt_len = sizeof(plaintext);
        unsigned char expected_ct[128];
        int expected_len = 0;
        int ret = 0;

        /* ---------- Compute expected ciphertext with EVP (reference) ---------- */
        EVP_CIPHER_CTX *ref_ctx = EVP_CIPHER_CTX_new();
        if (!TEST_ptr(ref_ctx))
            goto err;
        if (!TEST_true(EVP_EncryptInit_ex(ref_ctx, EVP_aes_256_cbc(),
                                         NULL, key, iv)))
            goto err;
        if (!TEST_true(EVP_EncryptUpdate(ref_ctx, expected_ct,
                                         &expected_len,
                                         plaintext, (int)pt_len)))
            goto err;
        {
            int fin_len = 0;
            if (!TEST_true(EVP_EncryptFinal_ex(ref_ctx, expected_ct + expected_len,
                                              &fin_len)))
                goto err;
            expected_len += fin_len;
        }
        EVP_CIPHER_CTX_free(ref_ctx);
        ref_ctx = NULL;

        /* ---------- Test BIO encryption ---------- */
        {
            BIO *mem = BIO_new(BIO_s_mem());
            BIO *cipher = BIO_new(BIO_f_cipher());

            if (!TEST_ptr(mem) || !TEST_ptr(cipher))
                goto err;

            BIO_push(cipher, mem);

            if (!TEST_true(BIO_set_cipher(cipher,
                                          EVP_aes_256_cbc(),
                                          key, iv, 1)))   /* encrypt */
                goto err;

            if (!TEST_int_eq(BIO_write(cipher, plaintext, (int)pt_len), (int)pt_len))
                goto err;

            if (!TEST_int_eq(BIO_flush(cipher), 1))
                goto err;

            /* read ciphertext from the underlying memory BIO */
            unsigned char enc_out[128];
            int enc_len = 0, r;
            while ((r = BIO_read(mem, enc_out + enc_len,
                                 (int)(sizeof(enc_out) - enc_len))) > 0) {
                enc_len += r;
            }
            if (!TEST_int_eq(enc_len, expected_len))
                goto err;
            if (!TEST_mem_eq(enc_out, enc_len, expected_ct, expected_len))
                goto err;

            BIO_free_all(cipher);   /* frees both cipher and mem */
        }

        /* ---------- Test BIO decryption (round‑trip) ---------- */
        {
            BIO *mem = BIO_new_mem_buf(expected_ct, expected_len);
            BIO *dec  = BIO_new(BIO_f_cipher());

            if (!TEST_ptr(mem) || !TEST_ptr(dec))
                goto err;

            BIO_push(dec, mem);

            if (!TEST_true(BIO_set_cipher(dec,
                                          EVP_aes_256_cbc(),
                                          key, iv, 0)))   /* decrypt */
                goto err;

            unsigned char dec_out[128];
            int dec_len = 0, r;
            while ((r = BIO_read(dec, dec_out + dec_len,
                                 (int)(sizeof(dec_out) - dec_len))) > 0) {
                dec_len += r;
            }
            if (!TEST_int_eq(dec_len, (int)pt_len))
                goto err;
            if (!TEST_mem_eq(dec_out, dec_len, plaintext, pt_len))
                goto err;

            BIO_free_all(dec);   /* frees both dec and mem */
        }

        ret = 1;
    err:
        if (ref_ctx != NULL)
            EVP_CIPHER_CTX_free(ref_ctx);
        return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
