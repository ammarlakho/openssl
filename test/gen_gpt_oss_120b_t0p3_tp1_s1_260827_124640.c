/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p3_tp1_s1_260827_124640.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
        const unsigned char key[32] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        };
        const unsigned char iv[16] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
        };
        const char *plaintext = "The quick brown fox jumps over the lazy dog";
        size_t pt_len = strlen(plaintext);
        unsigned char *enc_data = NULL;
        unsigned char *dec_buf = NULL;
        int ret = 0;
        BIO *mem_out = NULL, *enc_bio = NULL;
        BIO *mem_in = NULL, *dec_bio = NULL;
        char *enc_ptr = NULL;
        long enc_len = 0;

        /* ---------- encryption ---------- */
        mem_out = BIO_new(BIO_s_mem());
        if (!TEST_ptr(mem_out))
            goto end;
        enc_bio = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(enc_bio))
            goto end;
        if (!TEST_true(BIO_set_cipher(enc_bio, EVP_aes_256_cbc(),
                                    key, iv, 1)))
            goto end;
        /* push the filter on top of the memory BIO */
        enc_bio = BIO_push(enc_bio, mem_out);
        if (!TEST_int_eq(BIO_write(enc_bio,
                                  plaintext,
                                  (int)pt_len), (int)pt_len))
            goto end;
        if (!TEST_int_eq(BIO_flush(enc_bio), 1))
            goto end;

        /* obtain the ciphertext */
        enc_len = BIO_get_mem_data(mem_out, &enc_ptr);
        if (!TEST_int_gt(enc_len, 0))
            goto end;
        enc_data = OPENSSL_malloc((size_t)enc_len);
        if (!TEST_ptr(enc_data))
            goto end;
        memcpy(enc_data, enc_ptr, (size_t)enc_len);

        /* ---------- decryption ---------- */
        mem_in = BIO_new_mem_buf(enc_data, (int)enc_len);
        if (!TEST_ptr(mem_in))
            goto end;
        dec_bio = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(dec_bio))
            goto end;
        if (!TEST_true(BIO_set_cipher(dec_bio, EVP_aes_256_cbc(),
                                    key, iv, 0)))
            goto end;
        dec_bio = BIO_push(dec_bio, mem_in);

        dec_buf = OPENSSL_malloc(pt_len + EVP_MAX_BLOCK_LENGTH);
        if (!TEST_ptr(dec_buf))
            goto end;
        {
            int read_len = BIO_read(dec_bio,
                                   dec_buf,
                                   (int)(pt_len + EVP_MAX_BLOCK_LENGTH));
            if (!TEST_int_gt(read_len, 0))
                goto end;
            if (!TEST_mem_eq(dec_buf, read_len, plaintext, pt_len))
                goto end;
        }

        ret = 1; /* success */

    end:
        OPENSSL_free(enc_data);
        OPENSSL_free(dec_buf);
        /* BIO_free_all frees the whole chain (filter + underlying BIO) */
        BIO_free_all(enc_bio);
        BIO_free_all(dec_bio);
        return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
