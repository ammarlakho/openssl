/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p3_tp1_s6_260827_124855.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
        /* Test vector for AES‑256‑CBC */
        static const unsigned char key[32] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
            0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
        };
        static const unsigned char iv[16] = {
            0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,
            0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf
        };
        static const unsigned char plaintext[] =
            "OpenSSL BIO cipher test vector";
        const size_t pt_len = sizeof(plaintext) - 1; /* exclude NUL */

        /* -----------------------------------------------------------------
         * 1. Compute the expected ciphertext using the EVP API (no BIO).
         * ----------------------------------------------------------------- */
        unsigned char expected_ct[128];
        int evp_outlen = 0, evp_flen = 0;
        EVP_CIPHER_CTX *evp_ctx = EVP_CIPHER_CTX_new();
        if (!TEST_ptr(evp_ctx))
            return 0;
        if (!TEST_true(EVP_EncryptInit_ex(evp_ctx, EVP_aes_256_cbc(),
                                          NULL, key, iv)))
            goto err_evp;
        if (!TEST_true(EVP_EncryptUpdate(evp_ctx, expected_ct,
                                          &evp_outlen, plaintext, (int)pt_len)))
            goto err_evp;
        if (!TEST_true(EVP_EncryptFinal_ex(evp_ctx,
                                           expected_ct + evp_outlen,
                                           &evp_flen)))
            goto err_evp;
        EVP_CIPHER_CTX_free(evp_ctx);
        evp_ctx = NULL;
        const size_t ct_len = (size_t)(evp_outlen + evp_flen);

        /* -----------------------------------------------------------------
         * 2. Encrypt via BIO_f_cipher and compare with the expected ciphertext.
         * ----------------------------------------------------------------- */
        BIO *mem_enc = BIO_new(BIO_s_mem());
        BIO *bio_enc = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(mem_enc) || !TEST_ptr(bio_enc))
            goto err;
        if (!TEST_true(BIO_set_cipher(bio_enc, EVP_aes_256_cbc(),
                                      key, iv, 1)))   /* encrypt */
            goto err;
        BIO_push(bio_enc, mem_enc);

        if (!TEST_int_eq(BIO_write(bio_enc, (const char *)plaintext,
                                   (int)pt_len), (int)pt_len))
            goto err;
        if (!TEST_true(BIO_flush(bio_enc)))
            goto err;

        /* Retrieve ciphertext from the memory BIO */
        char *enc_data = NULL;
        long enc_len = BIO_get_mem_data(mem_enc, &enc_data);
        if (!TEST_int_eq(enc_len, (long)ct_len))
            goto err;
        if (!TEST_mem_eq(enc_data, (size_t)enc_len,
                         expected_ct, ct_len))
            goto err;

        /* -----------------------------------------------------------------
         * 3. Decrypt the ciphertext via BIO_f_cipher and verify we obtain the
         *    original plaintext.
         * ----------------------------------------------------------------- */
        BIO *mem_dec = BIO_new_mem_buf(enc_data, (int)enc_len);
        BIO *bio_dec = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(mem_dec) || !TEST_ptr(bio_dec))
            goto err;
        if (!TEST_true(BIO_set_cipher(bio_dec, EVP_aes_256_cbc(),
                                      key, iv, 0)))   /* decrypt */
            goto err;
        BIO_push(bio_dec, mem_dec);

        unsigned char dec_buf[128];
        size_t dec_total = 0;
        int r;
        while ((r = BIO_read(bio_dec,
                             (char *)dec_buf + dec_total,
                             (int)(sizeof(dec_buf) - dec_total))) > 0) {
            dec_total += (size_t)r;
            if (dec_total >= sizeof(dec_buf))
                break;
        }
        if (!TEST_int_gt((int)dec_total, 0))
            goto err;
        if (!TEST_int_eq((int)dec_total, (int)pt_len))
            goto err;
        if (!TEST_mem_eq(dec_buf, dec_total,
                         plaintext, pt_len))
            goto err;

        /* Clean up */
        BIO_free_all(bio_enc);
        BIO_free_all(bio_dec);
        return 1;

    err:
        if (evp_ctx)
            EVP_CIPHER_CTX_free(evp_ctx);
        BIO_free_all(bio_enc);
        BIO_free_all(bio_dec);
        return 0;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
