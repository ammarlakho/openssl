/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p2_tp0p95_fp0p3_s3_260827_002454.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
        /* Fixed test vectors */
        const unsigned char key[32] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
            0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
        };
        const unsigned char iv[16] = {
            0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,
            0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf
        };
        const unsigned char plaintext[] =
            "The quick brown fox jumps over the lazy dog";
        size_t pt_len = strlen((const char *)plaintext);

        /* ---------- Encryption ---------- */
        BIO *mem_enc = BIO_new(BIO_s_mem());
        if (!TEST_ptr(mem_enc))
            return 0;

        BIO *enc = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(enc)) {
            BIO_free(mem_enc);
            return 0;
        }

        if (!TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                    key, iv, 1))) {
            BIO_free_all(enc);
            BIO_free(mem_enc);
            return 0;
        }

        /* Chain: enc -> mem_enc */
        BIO_push(enc, mem_enc);

        if (!TEST_int_eq(BIO_write(enc, plaintext, (int)pt_len), (int)pt_len)) {
            BIO_free_all(enc);
            return 0;
        }

        if (!TEST_true(BIO_flush(enc))) {
            BIO_free_all(enc);
            return 0;
        }

        /* Retrieve encrypted data */
        char *enc_data_ptr = NULL;
        long enc_len = BIO_get_mem_data(mem_enc, &enc_data_ptr);
        if (!TEST_int_gt(enc_len, 0))
            return 0;

        /* Copy encrypted data because we will free the BIO chain */
        unsigned char *enc_copy = OPENSSL_malloc((size_t)enc_len);
        if (!TEST_ptr(enc_copy)) {
            BIO_free_all(enc);
            return 0;
        }
        memcpy(enc_copy, enc_data_ptr, (size_t)enc_len);

        /* Clean up encryption BIOs */
        BIO_free_all(enc); /* also frees mem_enc */

        /* ---------- Decryption ---------- */
        BIO *mem_dec_src = BIO_new_mem_buf(enc_copy, (int)enc_len);
        if (!TEST_ptr(mem_dec_src)) {
            OPENSSL_free(enc_copy);
            return 0;
        }

        BIO *dec = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(dec)) {
            BIO_free(mem_dec_src);
            OPENSSL_free(enc_copy);
            return 0;
        }

        if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                    key, iv, 0))) {
            BIO_free_all(dec);
            OPENSSL_free(enc_copy);
            return 0;
        }

        /* Chain: dec -> mem_dec_src */
        BIO_push(dec, mem_dec_src);

        unsigned char outbuf[256];
        int outlen = BIO_read(dec, outbuf, sizeof(outbuf));
        if (!TEST_int_eq(outlen, (int)pt_len)) {
            BIO_free_all(dec);
            OPENSSL_free(enc_copy);
            return 0;
        }

        if (!TEST_mem_eq(outbuf, (size_t)outlen, plaintext, pt_len)) {
            BIO_free_all(dec);
            OPENSSL_free(enc_copy);
            return 0;
        }

        /* Verify cipher status is OK */
        long status = BIO_ctrl(dec, BIO_C_GET_CIPHER_STATUS, 0, NULL);
        if (!TEST_int_eq(status, 1)) {
            BIO_free_all(dec);
            OPENSSL_free(enc_copy);
            return 0;
        }

        /* Clean up */
        BIO_free_all(dec);
        OPENSSL_free(enc_copy);

        return 1;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
