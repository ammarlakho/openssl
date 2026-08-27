/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p8_tp1_s3_260827_131012.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
        /* Test vectors */
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
            "The quick brown fox jumps over the lazy dog";
        const int pt_len = (int)sizeof(plaintext) - 1; /* no trailing NUL */

        /* -----------------------------------------------------------------
         * 1) Compute the expected ciphertext with the EVP API.
         * ----------------------------------------------------------------- */
        unsigned char exp_ct[128];
        int exp_len = 0, outlen = 0;
        EVP_CIPHER_CTX *evp_ctx = EVP_CIPHER_CTX_new();

        if (!TEST_ptr(evp_ctx))
            return 0;
        if (!TEST_true(EVP_EncryptInit_ex(evp_ctx, EVP_aes_256_cbc(),
                                          NULL, key, iv)))
            goto err;
        if (!TEST_true(EVP_EncryptUpdate(evp_ctx,
                                          exp_ct, &outlen,
                                          plaintext, pt_len)))
            goto err;
        exp_len = outlen;
        if (!TEST_true(EVP_EncryptFinal_ex(evp_ctx,
                                           exp_ct + exp_len, &outlen)))
            goto err;
        exp_len += outlen;
        EVP_CIPHER_CTX_free(evp_ctx);
        evp_ctx = NULL;

        /* -----------------------------------------------------------------
         * 2) Encrypt via BIO_f_cipher and compare with the expected ciphertext.
         * ----------------------------------------------------------------- */
        BIO *mem = BIO_new(BIO_s_mem());
        BIO *cipher = BIO_new(BIO_f_cipher());

        if (!TEST_ptr(mem) || !TEST_ptr(cipher))
            goto err;

        if (!TEST_true(BIO_set_cipher(cipher, EVP_aes_256_cbc(),
                                      key, iv, 1)))   /* 1 = encrypt */
            goto err;

        /* Chain: cipher -> mem */
        BIO_push(cipher, mem);

        if (!TEST_int_eq(BIO_write(cipher, plaintext, pt_len), pt_len))
            goto err;
        if (!TEST_true(BIO_flush(cipher)))
            goto err;

        /* Retrieve data from the memory BIO */
        BUF_MEM *bptr = NULL;
        if (!TEST_true(BIO_get_mem_ptr(mem, &bptr)))
            goto err;
        if (!TEST_int_eq((int)bptr->length, exp_len))
            goto err;
        if (!TEST_mem_eq(bptr->data, bptr->length, exp_ct, exp_len))
            goto err;

        /* -----------------------------------------------------------------
         * 3) Decrypt via BIO_f_cipher and verify we get the original plaintext.
         * ----------------------------------------------------------------- */
        BIO *mem_r = BIO_new_mem_buf(exp_ct, exp_len);
        BIO *dec = BIO_new(BIO_f_cipher());

        if (!TEST_ptr(mem_r) || !TEST_ptr(dec))
            goto err;

        if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                      key, iv, 0)))   /* 0 = decrypt */
            goto err;

        /* Chain: dec -> mem_r */
        BIO_push(dec, mem_r);

        unsigned char dec_buf[128];
        int dec_len = 0, total = 0;
        while ((dec_len = BIO_read(dec, dec_buf + total,
                                  sizeof(dec_buf) - total)) > 0) {
            total += dec_len;
            if (total >= sizeof(dec_buf))
                break;
        }
        if (!TEST_int_gt(total, 0))
            goto err;
        if (!TEST_int_eq(total, pt_len))
            goto err;
        if (!TEST_mem_eq(dec_buf, total, plaintext, pt_len))
            goto err;

        /* Clean up */
        BIO_free_all(cipher);
        BIO_free_all(dec);
        return 1;

    err:
        if (evp_ctx)
            EVP_CIPHER_CTX_free(evp_ctx);
        BIO_free_all(cipher);
        BIO_free_all(dec);
        BIO_free_all(mem);
        BIO_free_all(mem_r);
        return 0;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
