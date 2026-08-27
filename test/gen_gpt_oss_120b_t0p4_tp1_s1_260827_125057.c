/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p4_tp1_s1_260827_125057.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
        /* Test BIO_f_cipher encryption and decryption round‑trip using AES‑256‑CBC */
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
        const char *plain = "Test vector for AES-256-CBC encryption using BIO_f_cipher.";
        size_t plain_len = strlen(plain);
        unsigned char outbuf[1024];
        int outlen;
        BIO *bmem_in = NULL, *benc = NULL, *benc_out = NULL;
        BIO *bmem_cipher = NULL, *bdec = NULL, *bdec_out = NULL;
        EVP_CIPHER_CTX *cctx = NULL;
        const char *cipher_data = NULL;
        long cipher_len = 0;
        const char *decrypted = NULL;
        long decrypted_len = 0;
        int ret = 0; /* assume failure */

        /* ---------- encryption side ---------- */
        if (!TEST_ptr(bmem_in = BIO_new_mem_buf(plain, (int)plain_len)))
            goto err;
        if (!TEST_ptr(benc = BIO_new(BIO_f_cipher())))
            goto err;
        if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(),
                                      key, iv, 1)))   /* encrypt */
            goto err;
        /* push source under the cipher filter */
        benc = BIO_push(benc, bmem_in);

        if (!TEST_ptr(benc_out = BIO_new(BIO_s_mem())))
            goto err;

        /* read encrypted data from the filter and write it to the memory BIO */
        while ((outlen = BIO_read(benc, outbuf, sizeof(outbuf))) > 0) {
            if (!TEST_int_gt(BIO_write(benc_out, outbuf, outlen), 0))
                goto err;
        }
        /* finalize encryption */
        if (!TEST_int_eq(BIO_flush(benc), 1))
            goto err;
        /* there may be a final block left */
        while ((outlen = BIO_read(benc, outbuf, sizeof(outbuf))) > 0) {
            if (!TEST_int_gt(BIO_write(benc_out, outbuf, outlen), 0))
                goto err;
        }

        /* obtain ciphertext */
        if (!TEST_int_gt(BIO_get_mem_data(benc_out, &cipher_data), 0))
            goto err;
        cipher_len = BIO_get_mem_data(benc_out, NULL);
        if (!TEST_long_gt(cipher_len, 0))
            goto err;

        /* optional sanity check: the cipher context is accessible */
        if (!TEST_int_eq(BIO_ctrl(benc, BIO_C_GET_CIPHER_CTX, 0, &cctx), 1))
            goto err;
        if (!TEST_ptr(cctx))
            goto err;
        if (!TEST_int_eq(BIO_ctrl(benc, BIO_C_GET_CIPHER_STATUS, 0, NULL), 1))
            goto err;

        /* ---------- decryption side ---------- */
        if (!TEST_ptr(bmem_cipher = BIO_new_mem_buf(cipher_data,
                                                    (int)cipher_len)))
            goto err;
        if (!TEST_ptr(bdec = BIO_new(BIO_f_cipher())))
            goto err;
        if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(),
                                      key, iv, 0)))   /* decrypt */
            goto err;
        bdec = BIO_push(bdec, bmem_cipher);

        if (!TEST_ptr(bdec_out = BIO_new(BIO_s_mem())))
            goto err;

        while ((outlen = BIO_read(bdec, outbuf, sizeof(outbuf))) > 0) {
            if (!TEST_int_gt(BIO_write(bdec_out, outbuf, outlen), 0))
                goto err;
        }
        if (!TEST_int_eq(BIO_flush(bdec), 1))
            goto err;
        while ((outlen = BIO_read(bdec, outbuf, sizeof(outbuf))) > 0) {
            if (!TEST_int_gt(BIO_write(bdec_out, outbuf, outlen), 0))
                goto err;
        }

        if (!TEST_int_gt(BIO_get_mem_data(bdec_out, &decrypted), 0))
            goto err;
        decrypted_len = BIO_get_mem_data(bdec_out, NULL);
        if (!TEST_long_eq(decrypted_len, (long)plain_len))
            goto err;

        /* compare plaintext and decrypted data */
        if (!TEST_mem_eq(plain, plain_len, decrypted, (size_t)decrypted_len))
            goto err;

        /* all checks passed */
        ret = 1;

    err:
        BIO_free_all(benc);
        BIO_free_all(benc_out);
        BIO_free_all(bdec);
        BIO_free_all(bdec_out);
        return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
