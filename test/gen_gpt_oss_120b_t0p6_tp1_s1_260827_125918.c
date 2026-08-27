/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p6_tp1_s1_260827_125918.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
        const unsigned char key[32] = {0};
        const unsigned char iv[16] = {0};
        const char *plaintext = "OpenSSL BIO cipher round‑trip test";
        size_t pt_len = strlen(plaintext);
        BIO *mem = NULL, *enc = NULL, *dec = NULL, *mem_in = NULL;
        char *cdata = NULL;
        long c_len = 0;
        int ret = 0;
        int w, r;

        /* ---------- encryption ---------- */
        mem = BIO_new(BIO_s_mem());
        if (!TEST_ptr(mem))
            goto end;

        enc = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(enc))
            goto end;

        if (!TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                      key, iv, 1)))
            goto end;

        /* enc sits on top of mem */
        BIO_push(enc, mem);

        w = BIO_write(enc, plaintext, (int)pt_len);
        if (!TEST_int_gt(w, 0))
            goto end;

        if (!TEST_int_eq(BIO_flush(enc), 1))
            goto end;

        c_len = BIO_get_mem_data(mem, &cdata);
        if (!TEST_long_gt(c_len, 0))
            goto end;

        /* ---------- decryption ---------- */
        mem_in = BIO_new_mem_buf(cdata, (int)c_len);
        if (!TEST_ptr(mem_in))
            goto end;

        dec = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(dec))
            goto end;

        if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                      key, iv, 0)))
            goto end;

        BIO_push(dec, mem_in);

        r = BIO_read(dec, cdata, (int)sizeof(cdata));
        if (!TEST_int_gt(r, 0))
            goto end;

        if (!TEST_int_eq(r, (int)pt_len))
            goto end;

        if (!TEST_mem_eq(cdata, r, plaintext, pt_len))
            goto end;

        ret = 1; /* success */

    end:
        BIO_free_all(enc);   /* also frees mem */
        BIO_free_all(dec);   /* also frees mem_in */
        return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
