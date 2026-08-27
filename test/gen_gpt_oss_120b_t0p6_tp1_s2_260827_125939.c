/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p6_tp1_s2_260827_125939.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
        int ok = 1;
        const unsigned char key[32] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        };
        const unsigned char iv[16] = {
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d, 0x0e, 0x0f
        };
        const char *plaintext = "OpenSSL BIO cipher test vector";
        size_t pt_len = strlen(plaintext);
        BIO *bmem_enc = NULL, *bcipher_enc = NULL;
        BIO *bmem_dec = NULL, *bcipher_dec = NULL;
        unsigned char *enc_buf = NULL;
        unsigned char *out_buf = NULL;

        /* ----- Encryption ----- */
        bmem_enc = BIO_new(BIO_s_mem());
        bcipher_enc = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(bmem_enc) || !TEST_ptr(bcipher_enc))
            goto end;
        BIO_push(bcipher_enc, bmem_enc);
        if (!TEST_true(BIO_set_cipher(bcipher_enc,
                                      EVP_aes_256_cbc(),
                                      key, iv, 1)))
            goto end;

        if (!TEST_int_eq(BIO_write(bcipher_enc, plaintext, (int)pt_len), (int)pt_len))
            goto end;
        if (!TEST_true(BIO_flush(bcipher_enc)))
            goto end;

        /* Retrieve ciphertext from the memory BIO */
        {
            long enc_len = BIO_ctrl_pending(bmem_enc);
            if (!TEST_int_gt(enc_len, 0))
                goto end;
            enc_buf = OPENSSL_malloc(enc_len);
            if (!TEST_ptr(enc_buf))
                goto end;
            if (!TEST_int_eq(BIO_read(bmem_enc, enc_buf, (int)enc_len), (int)enc_len))
                goto end;
        }

        /* ----- Decryption ----- */
        bmem_dec = BIO_new_mem_buf(enc_buf, (int)BIO_ctrl_pending(bmem_enc));
        bcipher_dec = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(bmem_dec) || !TEST_ptr(bcipher_dec))
            goto end;
        BIO_push(bcipher_dec, bmem_dec);
        if (!TEST_true(BIO_set_cipher(bcipher_dec,
                                      EVP_aes_256_cbc(),
                                      key, iv, 0)))
            goto end;

        out_buf = OPENSSL_malloc(pt_len + EVP_MAX_BLOCK_LENGTH);
        if (!TEST_ptr(out_buf))
            goto end;
        {
            int dec_len = BIO_read(bcipher_dec,
                                   out_buf,
                                   (int)(pt_len + EVP_MAX_BLOCK_LENGTH));
            if (!TEST_int_gt(dec_len, 0))
                goto end;
            if (!TEST_mem_eq(out_buf, dec_len, plaintext, pt_len))
                goto end;
        }

        /* Verify cipher status is OK */
        if (!TEST_int_eq(BIO_ctrl(bcipher_dec, BIO_C_GET_CIPHER_STATUS, 0, NULL), 1))
            goto end;

    end:
        BIO_free_all(bcipher_enc);
        BIO_free_all(bcipher_dec);
        OPENSSL_free(enc_buf);
        OPENSSL_free(out_buf);
        return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
