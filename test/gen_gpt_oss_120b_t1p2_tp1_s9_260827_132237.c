/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t1p2_tp1_s9_260827_132237.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
        const unsigned char key[32] = { 0 };
        const unsigned char iv[16] = { 0 };
        const char plaintext[] = "OpenSSL BIO cipher round‑trip test data.";
        size_t pt_len = sizeof(plaintext) - 1;          /* omit trailing NUL */
        BIO *mem = NULL, *enc = NULL;
        char *cipher = NULL;
        long cipher_len = 0;
        unsigned char outbuf[256];
        int outlen = 0, ret = 0;
    
        /* ---------- encrypt ---------- */
        if (!TEST_ptr(mem = BIO_new(BIO_s_mem())))
            goto end;
        if (!TEST_ptr(enc = BIO_new(BIO_f_cipher())))
            goto end;
        if (!TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                     key, iv, 1)))      /* encrypt */
            goto end;
    
        /* chain enc on top of mem */
        enc = BIO_push(enc, mem);
    
        if (!TEST_int_eq(BIO_write(enc,
                                   plaintext,
                                   (int)pt_len), (int)pt_len))
            goto end;
        if (!TEST_true(BIO_flush(enc)))               /* final block */
            goto end;
    
        cipher_len = BIO_get_mem_data(mem, &cipher);
        if (!TEST_int_gt((int)cipher_len, 0))
            goto end;
    
        /* ---------- decrypt ---------- */
        {
            BIO *mem2 = NULL, *dec = NULL;
    
            if (!TEST_ptr(mem2 = BIO_new_mem_buf(cipher,
                                                (int)cipher_len)))
                goto end;
            if (!TEST_ptr(dec = BIO_new(BIO_f_cipher())))
                goto end;
            if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                          key, iv, 0)))  /* decrypt */
                goto end;
    
            dec = BIO_push(dec, mem2);
    
            outlen = 0;
            for (;;) {
                int r = BIO_read(dec,
                                outbuf + outlen,
                                (int)sizeof(outbuf) - outlen);
                if (r > 0) {
                    outlen += r;
                    continue;
                }
                if (r == 0)
                    break;
                if (!BIO_should_retry(dec))
                    break;
            }
    
            if (!TEST_int_eq(outlen, (int)pt_len))
                goto end;
            if (!TEST_mem_eq(outbuf, outlen,
                             plaintext, pt_len))
                goto end;
    
            BIO_free_all(dec);   /* frees mem2 as well */
        }
    
        ret = 1;   /* all tests passed */
    end:
        BIO_free_all(enc);   /* frees mem as well if not already freed */
        return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
