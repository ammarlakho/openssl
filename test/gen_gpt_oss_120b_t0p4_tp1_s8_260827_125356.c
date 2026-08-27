/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p4_tp1_s8_260827_125356.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
        /* Test AES‑256‑CBC BIO encryption/decryption round‑trip */
        const unsigned char key[32] = {0};
        const unsigned char iv[16] = {0};
        const unsigned char plaintext[] =
            "The quick brown fox jumps over the lazy dog";
        const size_t pt_len = sizeof(plaintext) - 1;
        BIO *mem = NULL, *enc = NULL;
        BIO *mem2 = NULL, *dec = NULL;
        char *cdata = NULL;
        long c_len = 0;
        unsigned char outbuf[256] = {0};
        int w, r;

        /* ---------- Encryption side ---------- */
        if (!TEST_ptr(mem = BIO_new(BIO_s_mem()))
            || !TEST_ptr(enc = BIO_new(BIO_f_cipher()))
            || !TEST_true(BIO_set_cipher(enc,
                                         EVP_aes_256_cbc(),
                                         key, iv, 1)))
            goto err;

        /* Chain: enc -> mem */
        BIO_push(enc, mem);

        w = BIO_write(enc, plaintext, (int)pt_len);
        if (!TEST_int_eq(w, (int)pt_len))
            goto err;

        if (!TEST_true(BIO_flush(enc)))
            goto err;

        c_len = BIO_get_mem_data(mem, &cdata);
        if (!TEST_int_gt(c_len, 0))
            goto err;

        /* ---------- Decryption side ---------- */
        if (!TEST_ptr(mem2 = BIO_new_mem_buf(cdata, (int)c_len))
            || !TEST_ptr(dec = BIO_new(BIO_f_cipher()))
            || !TEST_true(BIO_set_cipher(dec,
                                         EVP_aes_256_cbc(),
                                         key, iv, 0)))
            goto err;

        /* Chain: dec -> mem2 */
        BIO_push(dec, mem2);

        r = BIO_read(dec, outbuf, sizeof(outbuf));
        if (!TEST_int_eq(r, (int)pt_len))
            goto err;

        if (!TEST_mem_eq(outbuf, pt_len, plaintext, pt_len))
            goto err;

        /* Clean up */
        BIO_free_all(enc);
        BIO_free_all(dec);
        return 1;

    err:
        BIO_free_all(enc);
        BIO_free_all(dec);
        return 0;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
