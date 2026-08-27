/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p7_tp1_s9_260827_130801.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
        /* Test data */
        const unsigned char key[32] = {0};
        const unsigned char iv[16] = {0};
        const unsigned char plaintext[] = "Test plaintext for BIO cipher.";
        const int plen = sizeof(plaintext) - 1; /* exclude terminating NUL */

        /* ------------------------------------------------------------ */
        /* 1. Compute expected ciphertext using the EVP API (reference) */
        unsigned char expected[128];
        int evp_outlen1 = 0, evp_outlen2 = 0;
        EVP_CIPHER_CTX *evp_ctx = EVP_CIPHER_CTX_new();
        if (!TEST_ptr(evp_ctx))
            return 0;
        if (!TEST_true(EVP_EncryptInit_ex(evp_ctx, EVP_aes_256_cbc(),
                                         NULL, key, iv)))
            return 0;
        if (!TEST_true(EVP_EncryptUpdate(evp_ctx, expected, &evp_outlen1,
                                         plaintext, plen)))
            return 0;
        if (!TEST_true(EVP_EncryptFinal_ex(evp_ctx,
                                           expected + evp_outlen1,
                                           &evp_outlen2)))
            return 0;
        EVP_CIPHER_CTX_free(evp_ctx);
        const int evp_ct_len = evp_outlen1 + evp_outlen2;

        /* ------------------------------------------------------------ */
        /* 2. Encrypt via BIO_f_cipher and compare with the reference */
        BIO *mem_enc = BIO_new(BIO_s_mem());
        BIO *bio_enc = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(mem_enc) || !TEST_ptr(bio_enc))
            return 0;

        if (!TEST_true(BIO_set_cipher(bio_enc, EVP_aes_256_cbc(),
                                      key, iv, 1)))   /* 1 = encrypt */
            return 0;

        /* Chain: bio_enc -> mem_enc */
        BIO_push(bio_enc, mem_enc);

        if (!TEST_int_ge(BIO_write(bio_enc, plaintext, plen), plen))
            return 0;

        if (!TEST_int_eq(BIO_flush(bio_enc), 1))
            return 0;

        /* Retrieve the ciphertext from the memory BIO */
        char *enc_data = NULL;
        long enc_len = BIO_get_mem_data(mem_enc, &enc_data);
        if (!TEST_int_eq((int)enc_len, evp_ct_len))
            return 0;
        if (!TEST_mem_eq(enc_data, enc_len, expected, evp_ct_len))
            return 0;

        /* ------------------------------------------------------------ */
        /* 3. Decrypt the ciphertext via BIO_f_cipher and verify plaintext */
        BIO *mem_dec = BIO_new_mem_buf(enc_data, (int)enc_len);
        BIO *bio_dec = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(mem_dec) || !TEST_ptr(bio_dec))
            return 0;

        if (!TEST_true(BIO_set_cipher(bio_dec, EVP_aes_256_cbc(),
                                      key, iv, 0)))   /* 0 = decrypt */
            return 0;

        /* Chain: bio_dec -> mem_dec */
        BIO_push(bio_dec, mem_dec);

        unsigned char outbuf[128];
        int outlen = BIO_read(bio_dec, outbuf, sizeof(outbuf));
        if (!TEST_int_ge(outlen, plen))
            return 0;
        if (!TEST_mem_eq(outbuf, plen, plaintext, plen))
            return 0;

        /* ------------------------------------------------------------ */
        /* Cleanup */
        BIO_free_all(bio_enc);   /* also frees mem_enc */
        BIO_free_all(bio_dec);   /* also frees mem_dec */

        return 1;
    }
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
