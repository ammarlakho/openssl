/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t1p4_tp1_s9_260827_132806.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    {
        const unsigned char key[32] = {0};
        const unsigned char iv[16]  = {0};
        const unsigned char *pt = (const unsigned char *)
            "Test vector for BIO cipher AES-256-CBC";
        size_t pt_len = strlen((const char *)pt);

        /* ------------------------------------------------------------
         * Compute the expected ciphertext using the EVP API directly.
         * ------------------------------------------------------------ */
        unsigned char evp_ct[128];
        int evp_len = 0, evp_tmp = 0;
        EVP_CIPHER_CTX *evp_ctx = EVP_CIPHER_CTX_new();

        if (!TEST_ptr(evp_ctx))
            return 0;

        if (!TEST_true(EVP_CipherInit_ex(evp_ctx,
                                         EVP_aes_256_cbc(),
                                         NULL, key, iv, 1)))
            goto evp_cleanup;

        if (!TEST_true(EVP_CipherUpdate(evp_ctx, evp_ct, &evp_len,
                                        pt, (int)pt_len)))
            goto evp_cleanup;

        if (!TEST_true(EVP_CipherFinal_ex(evp_ctx,
                                          evp_ct + evp_len, &evp_tmp)))
            goto evp_cleanup;

        evp_len += evp_tmp;
        /* evp_ct[0..evp_len-1] now contains the expected ciphertext */

        /* ------------------------------------------------------------
         * Encrypt via BIO_f_cipher and compare with the expected CT.
         * ------------------------------------------------------------ */
        BIO *mem_enc = BIO_new(BIO_s_mem());
        BIO *bio_enc = BIO_new(BIO_f_cipher());

        if (!TEST_ptr(mem_enc) || !TEST_ptr(bio_enc))
            goto evp_cleanup;

        /* initialise the filter for encryption */
        if (!TEST_true(BIO_set_cipher(bio_enc,
                                      EVP_aes_256_cbc(),
                                      key, iv, 1)))
            goto enc_cleanup;

        /* push the filter on top of the memory sink */
        BIO_push(bio_enc, mem_enc);

        if (!TEST_int_eq(BIO_write(bio_enc, pt, (int)pt_len), (int)pt_len))
            goto enc_cleanup;

        if (!TEST_true(BIO_flush(bio_enc)))
            goto enc_cleanup;

        /* retrieve the encrypted bytes */
        BUF_MEM *bmem = NULL;
        BIO_get_mem_ptr(mem_enc, &bmem);
        if (!TEST_ptr(bmem))
            goto enc_cleanup;

        if (!TEST_int_eq(bmem->length, evp_len))
            goto enc_cleanup;

        if (!TEST_mem_eq(bmem->data, bmem->length,
                         evp_ct, evp_len))
            goto enc_cleanup;

        /* ------------------------------------------------------------
         * Decrypt via BIO_f_cipher and verify we obtain the original PT.
         * ------------------------------------------------------------ */
        BIO *mem_dec = BIO_new_mem_buf(bmem->data, bmem->length);
        BIO *bio_dec = BIO_new(BIO_f_cipher());

        if (!TEST_ptr(mem_dec) || !TEST_ptr(bio_dec))
            goto enc_cleanup;

        /* initialise the filter for decryption */
        if (!TEST_true(BIO_set_cipher(bio_dec,
                                      EVP_aes_256_cbc(),
                                      key, iv, 0)))
            goto dec_cleanup;

        BIO_push(bio_dec, mem_dec);

        unsigned char out_buf[256];
        int out_len = BIO_read(bio_dec, out_buf, sizeof(out_buf));
        if (!TEST_int_eq(out_len, (int)pt_len))
            goto dec_cleanup;

        if (!TEST_mem_eq(out_buf, out_len, pt, pt_len))
            goto dec_cleanup;

        /* Success – clean up and return */
        BIO_free_all(bio_enc);
        BIO_free_all(bio_dec);
        EVP_CIPHER_CTX_free(evp_ctx);
        return 1;

    dec_cleanup:
        BIO_free_all(bio_dec);
    enc_cleanup:
        BIO_free_all(bio_enc);
    evp_cleanup:
        EVP_CIPHER_CTX_free(evp_ctx);
        return 0;
    }
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
