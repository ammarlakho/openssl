/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p8_tp1_s1_260827_130857.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
        size_t pt_len = sizeof(plaintext) - 1;
        unsigned char expected[128];
        int outlen1 = 0, outlen2 = 0;
        EVP_CIPHER_CTX *cctx = NULL;
        BIO *mem = NULL, *enc = NULL;
        char *enc_data = NULL;
        long enc_len = 0;
        BIO *mem2 = NULL, *dec = NULL;
        unsigned char outbuf[128];
        int out_read = 0;
        int ret = 0;

        /* Produce the expected ciphertext using EVP API */
        cctx = EVP_CIPHER_CTX_new();
        if (!TEST_ptr(cctx))
            return 0;
        if (!TEST_true(EVP_EncryptInit_ex(cctx, EVP_aes_256_cbc(),
                                         NULL, key, iv))) {
            EVP_CIPHER_CTX_free(cctx);
            return 0;
        }
        if (!TEST_true(EVP_EncryptUpdate(cctx,
                                         expected, &outlen1,
                                         plaintext, (int)pt_len))) {
            EVP_CIPHER_CTX_free(cctx);
            return 0;
        }
        if (!TEST_true(EVP_EncryptFinal_ex(cctx,
                                          expected + outlen1, &outlen2))) {
            EVP_CIPHER_CTX_free(cctx);
            return 0;
        }
        EVP_CIPHER_CTX_free(cctx);
        int exp_len = outlen1 + outlen2;

        /* Encrypt via BIO_f_cipher */
        mem = BIO_new(BIO_s_mem());
        if (!TEST_ptr(mem))
            return 0;
        enc = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(enc)) {
            BIO_free(mem);
            return 0;
        }
        if (!TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                      key, iv, 1))) {
            BIO_free_all(enc);
            BIO_free(mem);
            return 0;
        }
        enc = BIO_push(enc, mem);
        if (!TEST_true(BIO_write(enc, plaintext, (int)pt_len) > 0)) {
            BIO_free_all(enc);
            return 0;
        }
        if (!TEST_true(BIO_flush(enc))) {
            BIO_free_all(enc);
            return 0;
        }

        /* Retrieve encrypted data from the memory BIO */
        enc_len = BIO_get_mem_data(mem, &enc_data);
        if (!TEST_int_gt(enc_len, 0))
            ret = 0;
        else if (!TEST_mem_eq(enc_data, (size_t)enc_len,
                             expected, (size_t)exp_len))
            ret = 0;

        if (!ret) {
            BIO_free_all(enc);
            return 0;
        }

        /* Decrypt via BIO_f_cipher */
        mem2 = BIO_new_mem_buf(enc_data, (int)enc_len);
        if (!TEST_ptr(mem2)) {
            BIO_free_all(enc);
            return 0;
        }
        dec = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(dec)) {
            BIO_free(mem2);
            BIO_free_all(enc);
            return 0;
        }
        if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                      key, iv, 0))) {
            BIO_free_all(dec);
            BIO_free(mem2);
            BIO_free_all(enc);
            return 0;
        }
        dec = BIO_push(dec, mem2);
        out_read = BIO_read(dec, outbuf, sizeof(outbuf));
        if (!TEST_int_gt(out_read, 0))
            ret = 0;
        else if (!TEST_int_eq(out_read, (int)pt_len))
            ret = 0;
        else if (!TEST_mem_eq(outbuf, (size_t)out_read,
                             plaintext, pt_len))
            ret = 0;

        BIO_free_all(dec);
        BIO_free_all(enc);
        return ret ? 1 : 0;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
