/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p5_tp1_s5_260827_125645.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
        const unsigned char plaintext[] =
            "The quick brown fox jumps over the lazy dog";
        const int plen = (int)sizeof(plaintext) - 1; /* without NUL */

        /* -----------------------------------------------------------------
         * 1. Produce the reference ciphertext with the EVP API.
         * ----------------------------------------------------------------- */
        unsigned char ref_ct[128];
        int outlen = 0, finallen = 0;
        EVP_CIPHER_CTX *ectx = EVP_CIPHER_CTX_new();

        if (!TEST_ptr(ectx))
            return 0;
        if (!TEST_true(EVP_EncryptInit_ex(ectx, EVP_aes_256_cbc(),
                                          NULL, key, iv)))
            goto err_ectx;
        if (!TEST_true(EVP_EncryptUpdate(ectx, ref_ct, &outlen,
                                          plaintext, plen)))
            goto err_ectx;
        if (!TEST_true(EVP_EncryptFinal_ex(ectx, ref_ct + outlen,
                                           &finallen)))
            goto err_ectx;
        EVP_CIPHER_CTX_free(ectx);
        ectx = NULL;
        const int ref_ct_len = outlen + finallen;

        /* -----------------------------------------------------------------
         * 2. Encrypt using the cipher BIO and compare with the reference.
         * ----------------------------------------------------------------- */
        BIO *mem = BIO_new(BIO_s_mem());
        BIO *enc = BIO_new(BIO_f_cipher());

        if (!TEST_ptr(mem) || !TEST_ptr(enc))
            goto err_cleanup;
        if (!TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                      key, iv, 1)))   /* encrypt = 1 */
            goto err_cleanup;

        BIO_push(enc, mem);
        if (!TEST_int_eq(BIO_write(enc, plaintext, plen), plen))
            goto err_cleanup;
        if (!TEST_true(BIO_flush(enc)))
            goto err_cleanup;

        char *enc_data = NULL;
        long enc_len = BIO_get_mem_data(mem, &enc_data);
        if (!TEST_int_eq((int)enc_len, ref_ct_len))
            goto err_cleanup;
        if (!TEST_mem_eq(enc_data, (size_t)enc_len,
                         ref_ct, (size_t)ref_ct_len))
            goto err_cleanup;

        /* Keep a copy of the ciphertext because we will free the BIOs next. */
        unsigned char ct_copy[128];
        memcpy(ct_copy, enc_data, (size_t)enc_len);
        const int ct_len = (int)enc_len;

        BIO_free_all(enc);      /* also frees mem */

        /* -----------------------------------------------------------------
         * 3. Decrypt using a fresh cipher BIO and verify we obtain the
         *    original plaintext.
         * ----------------------------------------------------------------- */
        BIO *mem_in = BIO_new_mem_buf(ct_copy, ct_len);
        BIO *dec = BIO_new(BIO_f_cipher());

        if (!TEST_ptr(mem_in) || !TEST_ptr(dec))
            goto err_cleanup;
        if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                      key, iv, 0)))   /* decrypt = 0 */
            goto err_cleanup;

        BIO_push(dec, mem_in);
        unsigned char outbuf[128];
        int out_total = 0, r;

        while ((r = BIO_read(dec, outbuf + out_total,
                            sizeof(outbuf) - out_total)) > 0) {
            out_total += r;
        }
        if (!TEST_int_eq(out_total, plen))
            goto err_cleanup;
        if (!TEST_mem_eq(outbuf, (size_t)out_total,
                         plaintext, (size_t)plen))
            goto err_cleanup;

        BIO_free_all(dec);
        return 1;

    err_ectx:
        EVP_CIPHER_CTX_free(ectx);
    err_cleanup:
        BIO_free_all(enc);
        BIO_free_all(dec);
        BIO_free(mem);
        BIO_free(mem_in);
        return 0;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
