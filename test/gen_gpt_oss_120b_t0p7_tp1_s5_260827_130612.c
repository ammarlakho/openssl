/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p7_tp1_s5_260827_130612.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
        int ret = 1;
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
        const unsigned char plaintext[] =
            "OpenSSL BIO cipher round‑trip test vector";
        const size_t pt_len = sizeof(plaintext) - 1; /* exclude NUL */

        /* ---------- Encrypt ---------- */
        BIO *mem_enc = BIO_new(BIO_s_mem());
        BIO *cipher_enc = BIO_new(BIO_f_cipher());

        if (!TEST_ptr(mem_enc) || !TEST_ptr(cipher_enc))
            return 0;

        /* set up encrypting BIO */
        if (!TEST_true(BIO_set_cipher(cipher_enc,
                                      EVP_aes_256_cbc(),
                                      key, iv, 1)))
            ret = 0;

        BIO_push(cipher_enc, mem_enc);

        if (!TEST_int_eq(BIO_write(cipher_enc,
                                   (const char *)plaintext, (int)pt_len),
                         (int)pt_len))
            ret = 0;

        if (!TEST_int_ge(BIO_flush(cipher_enc), 0))
            ret = 0;

        /* obtain ciphertext from memory BIO */
        char *cdata = NULL;
        long c_len = BIO_get_mem_data(mem_enc, &cdata);
        if (!TEST_int_gt(c_len, 0) || !TEST_ptr(cdata))
            ret = 0;

        /* ---------- Decrypt ---------- */
        BIO *mem_dec = BIO_new_mem_buf(cdata, (int)c_len);
        BIO *cipher_dec = BIO_new(BIO_f_cipher());

        if (!TEST_ptr(mem_dec) || !TEST_ptr(cipher_dec))
            ret = 0;

        if (!TEST_true(BIO_set_cipher(cipher_dec,
                                      EVP_aes_256_cbc(),
                                      key, iv, 0)))
            ret = 0;

        BIO_push(cipher_dec, mem_dec);

        unsigned char outbuf[256];
        int outlen = 0, total = 0;
        while ((outlen = BIO_read(cipher_dec,
                                  outbuf + total,
                                  sizeof(outbuf) - total)) > 0) {
            total += outlen;
            if (total >= (int)sizeof(outbuf))
                break; /* safety */
        }

        if (!TEST_int_ge(outlen, 0))
            ret = 0;
        if (!TEST_int_eq(total, (int)pt_len))
            ret = 0;
        if (!TEST_mem_eq(outbuf, total, plaintext, pt_len))
            ret = 0;

        /* clean up */
        BIO_free_all(cipher_enc);
        BIO_free_all(cipher_dec);
        return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
