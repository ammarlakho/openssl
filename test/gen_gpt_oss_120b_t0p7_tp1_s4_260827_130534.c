/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p7_tp1_s4_260827_130534.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
        /* Fixed test vector for AES‑256‑CBC (NIST SP 800‑38A style) */
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
        static const unsigned char plaintext[] =
            "The quick brown fox jumps over the lazy dog";
        const int pt_len = (int)sizeof(plaintext) - 1;

        /* -----------------------------------------------------------------
         * Compute the expected ciphertext using the EVP API (no BIO involved).
         * ----------------------------------------------------------------- */
        unsigned char expected_ct[256];
        int expected_len = 0, outlen = 0;
        EVP_CIPHER_CTX *evp = EVP_CIPHER_CTX_new();
        if (!TEST_ptr(evp))
            return 0;
        if (!TEST_true(EVP_EncryptInit_ex(evp, EVP_aes_256_cbc(),
                                         NULL, key, iv)))
            goto err_evp;
        if (!TEST_true(EVP_EncryptUpdate(evp,
                                         expected_ct, &outlen,
                                         plaintext, pt_len)))
            goto err_evp;
        expected_len = outlen;
        if (!TEST_true(EVP_EncryptFinal_ex(evp,
                                          expected_ct + expected_len,
                                          &outlen)))
            goto err_evp;
        expected_len += outlen;
        EVP_CIPHER_CTX_free(evp);
        evp = NULL;

        /* -----------------------------------------------------------------
         * Encrypt using the cipher BIO and compare with the expected ciphertext.
         * ----------------------------------------------------------------- */
        BIO *mem_enc = BIO_new(BIO_s_mem());
        BIO *benc = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(mem_enc) || !TEST_ptr(benc))
            goto err_cleanup;

        if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(),
                                      key, iv, 1)))   /* encrypt */
            goto err_cleanup;

        BIO_push(benc, mem_enc);
        if (!TEST_int_eq(BIO_write(benc, plaintext, pt_len), pt_len))
            goto err_cleanup;
        if (!TEST_true(BIO_flush(benc)))
            goto err_cleanup;

        /* Retrieve the encrypted data from the memory BIO */
        char *enc_data = NULL;
        long enc_len = BIO_get_mem_data(mem_enc, &enc_data);
        if (!TEST_int_eq((int)enc_len, expected_len))
            goto err_cleanup;
        if (!TEST_mem_eq(enc_data, enc_len, expected_ct, expected_len))
            goto err_cleanup;

        /* -----------------------------------------------------------------
         * Decrypt the data using a second cipher BIO and verify we get the
         * original plaintext back.
         * ----------------------------------------------------------------- */
        BIO *mem_dec = BIO_new_mem_buf(enc_data, (int)enc_len);
        BIO *bdec = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(mem_dec) || !TEST_ptr(bdec))
            goto err_cleanup_dec;

        if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(),
                                      key, iv, 0)))   /* decrypt */
            goto err_cleanup_dec;

        BIO_push(bdec, mem_dec);
        unsigned char outbuf[256];
        int out_total = 0, r;
        while ((r = BIO_read(bdec, outbuf + out_total,
                            sizeof(outbuf) - out_total)) > 0) {
            out_total += r;
        }
        if (!TEST_int_eq(out_total, pt_len))
            goto err_cleanup_dec;
        if (!TEST_mem_eq(outbuf, out_total, plaintext, pt_len))
            goto err_cleanup_dec;

        /* Clean up */
        BIO_free_all(benc);   /* also frees mem_enc */
        BIO_free_all(bdec);   /* also frees mem_dec */
        return 1;

    err_cleanup_dec:
        BIO_free_all(bdec);
        BIO_free(mem_dec);
    err_cleanup:
        BIO_free_all(benc);
        BIO_free(mem_enc);
        if (evp != NULL)
            EVP_CIPHER_CTX_free(evp);
        return 0;
    err_evp:
        EVP_CIPHER_CTX_free(evp);
        return 0;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
