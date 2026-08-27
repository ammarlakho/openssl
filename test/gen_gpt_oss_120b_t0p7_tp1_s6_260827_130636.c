/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p7_tp1_s6_260827_130636.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
        /* Test vectors (AES‑256‑CBC) */
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
        static const unsigned char plaintext[16] = {
            0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
            0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
        };
        static const unsigned char expected_ct[16] = {
            0xf5,0x8c,0x4c,0x04,0xd6,0xe5,0xf1,0xba,
            0x77,0x9e,0xab,0xfb,0x5f,0x7b,0xfb,0xd6
        };
        BIO *bmem = NULL, *bcipher = NULL;
        BUF_MEM *bptr = NULL;
        unsigned char outbuf[64];
        int outlen;

        /* ---------- Encryption ---------- */
        bmem = BIO_new(BIO_s_mem());
        if (!TEST_ptr(bmem))
            return 0;
        bcipher = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(bcipher)) {
            BIO_free(bmem);
            return 0;
        }
        if (!TEST_true(BIO_set_cipher(bcipher, EVP_aes_256_cbc(),
                                    key, iv, 1))) {
            BIO_free_all(bcipher);
            return 0;
        }
        /* chain: bcipher -> bmem */
        bcipher = BIO_push(bcipher, bmem);

        if (!TEST_int_eq(BIO_write(bcipher, plaintext, sizeof(plaintext)),
                         sizeof(plaintext))) {
            BIO_free_all(bcipher);
            return 0;
        }
        if (!TEST_true(BIO_flush(bcipher))) {
            BIO_free_all(bcipher);
            return 0;
        }

        /* Retrieve ciphertext from memory BIO */
        BIO_get_mem_ptr(bmem, &bptr);
        if (!TEST_ptr(bptr))
            return 0;
        if (!TEST_int_eq((int)bptr->length, (int)sizeof(expected_ct)))
            return 0;
        if (!TEST_mem_eq(bptr->data, bptr->length,
                         expected_ct, sizeof(expected_ct))) {
            BIO_free_all(bcipher);
            return 0;
        }

        /* ---------- Decryption ---------- */
        {
            BIO *src = NULL, *bdec = NULL;
            src = BIO_new_mem_buf(bptr->data, (int)bptr->length);
            if (!TEST_ptr(src)) {
                BIO_free_all(bcipher);
                return 0;
            }
            bdec = BIO_new(BIO_f_cipher());
            if (!TEST_ptr(bdec)) {
                BIO_free(src);
                BIO_free_all(bcipher);
                return 0;
            }
            if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(),
                                          key, iv, 0))) {
                BIO_free(src);
                BIO_free_all(bcipher);
                return 0;
            }
            bdec = BIO_push(bdec, src);

            outlen = BIO_read(bdec, outbuf, sizeof(outbuf));
            if (!TEST_int_eq(outlen, (int)sizeof(plaintext))) {
                BIO_free_all(bdec);
                BIO_free_all(bcipher);
                return 0;
            }
            if (!TEST_mem_eq(outbuf, outlen, plaintext, sizeof(plaintext))) {
                BIO_free_all(bdec);
                BIO_free_all(bcipher);
                return 0;
            }
            BIO_free_all(bdec);
        }

        BIO_free_all(bcipher);
        return 1;
    }
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
