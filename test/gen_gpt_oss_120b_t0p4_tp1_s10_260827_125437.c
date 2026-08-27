/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p4_tp1_s10_260827_125437.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
        int ret = 0;
        const unsigned char key[32] = {0};
        const unsigned char iv[16] = {0};
        const char plaintext[] = "The quick brown fox jumps over the lazy dog";
        const size_t pt_len = strlen(plaintext);
        BIO *mem_enc = NULL, *cipher_enc = NULL;
        BIO *mem_dec = NULL, *cipher_dec = NULL;
        char *enc_buf = NULL;
        long enc_len = 0;
        unsigned char out_buf[128] = {0};
        int out_len = 0;

        /* ---------- Encryption side ---------- */
        if (!TEST_ptr(mem_enc = BIO_new(BIO_s_mem())))
            goto end;
        if (!TEST_ptr(cipher_enc = BIO_new(BIO_f_cipher())))
            goto end;
        BIO_push(cipher_enc, mem_enc);

        if (!TEST_true(BIO_set_cipher(cipher_enc, EVP_aes_256_cbc(),
                                    key, iv, 1)))   /* encrypt */
            goto end;

        if (!TEST_int_eq(BIO_write(cipher_enc, plaintext, (int)pt_len), (int)pt_len))
            goto end;

        if (!TEST_int_eq(BIO_flush(cipher_enc), 1))
            goto end;

        /* Retrieve encrypted data from the memory BIO */
        if (!TEST_int_gt((enc_len = BIO_get_mem_data(mem_enc, &enc_buf)), 0))
            goto end;
        if (!TEST_int_eq(enc_len % EVP_CIPHER_block_size(EVP_aes_256_cbc()), 0))
            goto end;
        if (!TEST_int_gt(enc_len, (long)pt_len))
            goto end;

        /* ---------- Decryption side ---------- */
        if (!TEST_ptr(mem_dec = BIO_new_mem_buf(enc_buf, (int)enc_len)))
            goto end;
        if (!TEST_ptr(cipher_dec = BIO_new(BIO_f_cipher())))
            goto end;
        BIO_push(cipher_dec, mem_dec);

        if (!TEST_true(BIO_set_cipher(cipher_dec, EVP_aes_256_cbc(),
                                    key, iv, 0)))   /* decrypt */
            goto end;

        out_len = BIO_read(cipher_dec, out_buf, sizeof(out_buf));
        if (!TEST_int_eq(out_len, (int)pt_len))
            goto end;

        if (!TEST_mem_eq(out_buf, out_len, plaintext, pt_len))
            goto end;

        ret = 1;   /* success */

    end:
        BIO_free_all(cipher_enc);   /* also frees mem_enc */
        BIO_free_all(cipher_dec);   /* also frees mem_dec */
        return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
