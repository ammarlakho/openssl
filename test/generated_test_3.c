/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: generated_test_3.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio(void)
{
    /* BEGIN_LLM_REPLACE */
        /* Test AES‑256‑CBC encryption/decryption using BIO_f_cipher against known vectors */
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
            "OpenSSL BIO cipher AES‑256‑CBC test vector.";
        const size_t ptlen = sizeof(plaintext) - 1; /* without trailing NUL */
        unsigned char *expected = NULL;
        int expected_len = 0;
        EVP_CIPHER_CTX *cctx = NULL;
        int outlen = 0, tmplen = 0;
        int ret = 0;

        /* ------------------------------------------------------------
         * 1. Produce the reference ciphertext with the EVP API.
         * ------------------------------------------------------------ */
        cctx = EVP_CIPHER_CTX_new();
        if (!TEST_ptr(cctx))
            goto err;
        if (!TEST_true(EVP_EncryptInit_ex(cctx, EVP_aes_256_cbc(),
                                          NULL, key, iv)))
            goto err;

        expected = OPENSSL_malloc(ptlen + EVP_MAX_BLOCK_LENGTH);
        if (!TEST_ptr(expected))
            goto err;

        if (!TEST_true(EVP_EncryptUpdate(cctx, expected, &outlen,
                                          plaintext, (int)ptlen)))
            goto err;
        expected_len = outlen;

        if (!TEST_true(EVP_EncryptFinal_ex(cctx, expected + outlen, &tmplen)))
            goto err;
        expected_len += tmplen;
        EVP_CIPHER_CTX_free(cctx);
        cctx = NULL;

        /* ------------------------------------------------------------
         * 2. Encrypt via the cipher BIO and compare with the reference.
         * ------------------------------------------------------------ */
        {
            BIO *mem = BIO_new(BIO_s_mem());
            BIO *benc = BIO_new(BIO_f_cipher());

            if (!TEST_ptr(mem) || !TEST_ptr(benc))
                goto err;

            if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(),
                                          key, iv, 1)))   /* encrypt */
                goto err;

            /* chain: benc -> mem */
            benc = BIO_push(benc, mem);

            if (!TEST_int_gt(BIO_write(benc, plaintext, (int)ptlen), 0))
                goto err;
            if (!TEST_true(BIO_flush(benc)))
                goto err;

            /* retrieve ciphertext from the memory BIO */
            char *bio_out = NULL;
            long bio_len = BIO_get_mem_data(mem, &bio_out);
            if (!TEST_int_eq(bio_len, expected_len))
                goto err;
            if (!TEST_mem_eq(bio_out, (size_t)bio_len,
                             expected, (size_t)expected_len))
                goto err;

            BIO_free_all(benc); /* frees both benc and mem */
        }

        /* ------------------------------------------------------------
         * 3. Decrypt via the cipher BIO and verify we obtain the original.
         * ------------------------------------------------------------ */
        {
            BIO *mem = BIO_new_mem_buf(expected, expected_len);
            BIO *bdec = BIO_new(BIO_f_cipher());

            if (!TEST_ptr(mem) || !TEST_ptr(bdec))
                goto err;

            if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(),
                                          key, iv, 0)))   /* decrypt */
                goto err;

            bdec = BIO_push(bdec, mem);

            unsigned char *outbuf = OPENSSL_malloc(expected_len);
            if (!TEST_ptr(outbuf))
                goto err;

            int readtotal = 0;
            int r;
            while ((r = BIO_read(bdec, outbuf + readtotal,
                                 (int)(expected_len - readtotal))) > 0) {
                readtotal += r;
            }
            if (!TEST_int_eq(readtotal, (int)ptlen))
                goto err;
            if (!TEST_mem_eq(outbuf, (size_t)readtotal,
                             plaintext, ptlen))
                goto err;

            OPENSSL_free(outbuf);
            BIO_free_all(bdec);
        }

        ret = 1;   /* all checks succeeded */
    err:
        if (cctx)
            EVP_CIPHER_CTX_free(cctx);
        if (expected)
            OPENSSL_free(expected);
        return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio);
    return 1;
}
