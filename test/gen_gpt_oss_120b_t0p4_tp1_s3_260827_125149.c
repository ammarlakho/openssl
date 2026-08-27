/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p4_tp1_s3_260827_125149.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
        /* Need <openssl/buffer.h> for BUF_MEM */
        const unsigned char key[32] = {
            0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
            0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
            0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
            0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
        };
        const unsigned char iv[16] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
        };
        const unsigned char plaintext[16] = {
            'S','i','n','g','l','e',' ','b','l','o','c','k',' ','m','s','g'
        };
        const unsigned char expected_ct[16] = {
            0xf5,0x8c,0x4c,0x04,0xd6,0xe5,0xf1,0xba,
            0x77,0x9e,0xab,0xfb,0x5f,0x7b,0xfb,0xd6
        };
        BIO *mem = NULL, *enc = NULL;
        BIO *mem_in = NULL, *dec = NULL;
        BUF_MEM *bptr = NULL;
        unsigned char outbuf[16];
        int outlen = 0, ret = 0;

        /* ---------- Encryption ---------- */
        mem = BIO_new(BIO_s_mem());
        if (!TEST_ptr(mem))
            goto err;
        enc = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(enc))
            goto err;
        if (!TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                    key, iv, 1)))
            goto err;
        BIO_push(enc, mem);

        if (!TEST_int_eq(BIO_write(enc, (const char *)plaintext,
                                   sizeof(plaintext)), sizeof(plaintext)))
            goto err;
        if (!TEST_true(BIO_flush(enc)))
            goto err;

        /* Retrieve ciphertext from memory BIO */
        BIO_get_mem_ptr(mem, &bptr);
        if (!TEST_ptr(bptr))
            goto err;
        if (!TEST_int_eq(bptr->length, (int)sizeof(expected_ct)))
            goto err;
        if (!TEST_mem_eq(bptr->data, bptr->length,
                         expected_ct, sizeof(expected_ct)))
            goto err;

        /* ---------- Decryption ---------- */
        mem_in = BIO_new_mem_buf(bptr->data, bptr->length);
        if (!TEST_ptr(mem_in))
            goto err;
        dec = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(dec))
            goto err;
        if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                    key, iv, 0)))
            goto err;
        BIO_push(dec, mem_in);

        /* Read decrypted data (may require a loop) */
        outlen = 0;
        while (outlen < (int)sizeof(outbuf)) {
            int r = BIO_read(dec,
                             (char *)outbuf + outlen,
                             sizeof(outbuf) - outlen);
            if (r <= 0) {
                if (!BIO_should_retry(dec))
                    break;
                continue;
            }
            outlen += r;
        }
        if (!TEST_int_eq(outlen, (int)sizeof(plaintext)))
            goto err;
        if (!TEST_mem_eq(outbuf, outlen,
                         plaintext, sizeof(plaintext)))
            goto err;

        ret = 1; /* success */

    err:
        BIO_free_all(enc);
        BIO_free_all(mem);
        BIO_free_all(dec);
        BIO_free_all(mem_in);
        return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
