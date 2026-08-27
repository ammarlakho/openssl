/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t1p4_tp1_s8_260827_132745.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
        /* Fixed test vector */
        const unsigned char key[32] = {0};
        const unsigned char iv[16] = {0};
        const unsigned char plaintext[] = "Test data for BIO cipher.";
        const size_t pt_len = sizeof(plaintext) - 1; /* omit terminating NUL */

        /* ------------------------------------------------------------ */
        /* 1. Encrypt using BIO_f_cipher on top of a memory BIO */
        BIO *mem = BIO_new(BIO_s_mem());
        BIO *enc = BIO_new(BIO_f_cipher());

        if (!TEST_ptr(mem) || !TEST_ptr(enc))
            return 0;

        if (!TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                      key, iv, 1 /* encrypt */)))
            goto err;

        /* Chain: enc -> mem */
        BIO_push(enc, mem);

        if (!TEST_int_eq(BIO_write(enc, plaintext, (int)pt_len), (int)pt_len))
            goto err;

        /* Ensure final block is flushed */
        if (!TEST_int_eq(BIO_ctrl(enc, BIO_CTRL_FLUSH, 0, NULL), 1))
            goto err;

        /* Retrieve ciphertext from memory BIO */
        char *cipher_buf = NULL;
        long cipher_len = BIO_get_mem_data(mem, &cipher_buf);
        if (!TEST_int_gt(cipher_len, 0))
            goto err;

        /* Ciphertext must not be identical to plaintext */
        if (!TEST_true(cipher_len != (long)pt_len ||
                     memcmp(cipher_buf, plaintext, pt_len) != 0))
            goto err;

        /* ------------------------------------------------------------ */
        /* 2. Decrypt using a new BIO_f_cipher on top of a memory source */
        BIO *mem_src = BIO_new_mem_buf(cipher_buf, (int)cipher_len);
        BIO *dec = BIO_new(BIO_f_cipher());

        if (!TEST_ptr(mem_src) || !TEST_ptr(dec))
            goto err;

        if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                      key, iv, 0 /* decrypt */)))
            goto err;

        /* Chain: dec -> mem_src */
        BIO_push(dec, mem_src);

        /* Read back the plaintext */
        unsigned char out_buf[512];
        int total_read = 0;
        while (total_read < (int)pt_len) {
            int r = BIO_read(dec, out_buf + total_read,
                             (int)(pt_len - total_read));
            if (r <= 0) {
                if (!BIO_should_retry(dec))
                    break;
                continue;
            }
            total_read += r;
        }

        if (!TEST_int_eq(total_read, (int)pt_len))
            goto err;

        if (!TEST_mem_eq(out_buf, total_read, plaintext, pt_len))
            goto err;

        /* ------------------------------------------------------------ */
        /* Cleanup */
        BIO_free_all(enc);   /* frees both enc and mem */
        BIO_free_all(dec);   /* frees both dec and mem_src */
        return 1;

    err:
        BIO_free_all(enc);
        BIO_free_all(dec);
        return 0;
    }
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
