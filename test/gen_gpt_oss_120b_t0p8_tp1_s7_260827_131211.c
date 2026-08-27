/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p8_tp1_s7_260827_131211.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
        const unsigned char key[32] = {0};
        const unsigned char iv[16] = {0};
        const char *plaintext =
            "OpenSSL BIO cipher test data for AES-256 CBC mode.";
        size_t pt_len = strlen(plaintext);
        unsigned char *ct = NULL;
        long ct_len = 0;
        const char *ct_data = NULL;

        /* ---------- Encryption ---------- */
        BIO *sink = BIO_new(BIO_s_mem());
        BIO *enc = BIO_new(BIO_f_cipher());

        if (!TEST_ptr(sink) || !TEST_ptr(enc))
            return 0;

        if (!TEST_true(BIO_set_cipher(enc,
                                      EVP_aes_256_cbc(),
                                      key, iv, 1))) {
            ok = 0;
            goto enc_cleanup;
        }

        /* Build chain: enc -> sink */
        BIO_push(enc, sink);

        if (!TEST_int_eq(BIO_write(enc,
                                   plaintext,
                                   (int)pt_len), (int)pt_len)) {
            ok = 0;
            goto enc_cleanup;
        }

        if (!TEST_int_eq(BIO_flush(enc), 1)) {
            ok = 0;
            goto enc_cleanup;
        }

        ct_len = BIO_get_mem_data(sink, &ct_data);
        if (!TEST_long_gt(ct_len, 0)) {
            ok = 0;
            goto enc_cleanup;
        }

        ct = OPENSSL_malloc((size_t)ct_len);
        if (!TEST_ptr(ct)) {
            ok = 0;
            goto enc_cleanup;
        }
        memcpy(ct, ct_data, (size_t)ct_len);

    enc_cleanup:
        BIO_free_all(enc);   /* also frees sink */

        if (!ok) {
            OPENSSL_free(ct);
            return 0;
        }

        /* ---------- Decryption ---------- */
        BIO *src = BIO_new_mem_buf(ct, (int)ct_len);
        BIO *dec = BIO_new(BIO_f_cipher());

        if (!TEST_ptr(src) || !TEST_ptr(dec)) {
            ok = 0;
            goto dec_cleanup;
        }

        if (!TEST_true(BIO_set_cipher(dec,
                                      EVP_aes_256_cbc(),
                                      key, iv, 0))) {
            ok = 0;
            goto dec_cleanup;
        }

        /* Build chain: dec -> src */
        BIO_push(dec, src);

        unsigned char outbuf[1024];
        int outlen = BIO_read(dec, outbuf, sizeof(outbuf));

        if (!TEST_int_gt(outlen, 0))
            ok = 0;
        else if (!TEST_mem_eq(outbuf, outlen, plaintext, pt_len))
            ok = 0;

    dec_cleanup:
        BIO_free_all(dec);   /* also frees src */
        OPENSSL_free(ct);
        return ok ? 1 : 0;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
