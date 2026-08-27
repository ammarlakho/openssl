/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p7_tp1_s8_260827_130726.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
static int test_bio_enc_generated(void)
{
    /* Test vector (AES‑256‑CBC, NIST SP 800‑38A) */
    static const unsigned char key[32] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
        0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };
    static const unsigned char iv[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const unsigned char plaintext[16] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
    };
    static const unsigned char expected_ct[16] = {
        0xf3,0xee,0xd1,0xbd,0xb5,0xd2,0xa0,0x3c,
        0x06,0x4b,0x5a,0x7e,0x3d,0xb1,0x81,0xf8
    };

    BIO *enc_filter = NULL, *enc_sink = NULL;
    BIO *dec_src = NULL, *dec_filter = NULL;
    char *enc_data = NULL;
    long enc_len = 0;
    int w, r;
    unsigned char outbuf[sizeof(plaintext)];
    int ok = 0;                     /* assume failure */

    /* ---------- Encryption ---------- */
    if (!TEST_ptr(enc_filter = BIO_new(BIO_f_cipher())))
        goto cleanup;
    if (!TEST_true(BIO_set_cipher(enc_filter,
                                 EVP_aes_256_cbc(),
                                 key, iv, 1)))      /* encrypt */
        goto cleanup;
    if (!TEST_ptr(enc_sink = BIO_new(BIO_s_mem())))
        goto cleanup;

    BIO_push(enc_filter, enc_sink);               /* enc_filter → enc_sink */

    w = BIO_write(enc_filter, plaintext, sizeof(plaintext));
    if (!TEST_int_eq(w, sizeof(plaintext)))
        goto cleanup;
    if (!TEST_true(BIO_flush(enc_filter)))
        goto cleanup;

    enc_len = BIO_get_mem_data(enc_sink, &enc_data);
    if (!TEST_int_gt(enc_len, 0))
        goto cleanup;
    if (!TEST_mem_eq(enc_data, (size_t)enc_len,
                     expected_ct, sizeof(expected_ct)))
        goto cleanup;

    /* ---------- Decryption ---------- */
    if (!TEST_ptr(dec_src = BIO_new_mem_buf(expected_ct,
                                            sizeof(expected_ct))))
        goto cleanup;
    if (!TEST_ptr(dec_filter = BIO_new(BIO_f_cipher())))
        goto cleanup;
    if (!TEST_true(BIO_set_cipher(dec_filter,
                                 EVP_aes_256_cbc(),
                                 key, iv, 0)))      /* decrypt */
        goto cleanup;

    BIO_push(dec_filter, dec_src);                /* dec_filter → dec_src */

    r = BIO_read(dec_filter, outbuf, sizeof(outbuf));
    if (!TEST_int_eq(r, sizeof(outbuf)))
        goto cleanup;
    if (!TEST_mem_eq(outbuf, sizeof(outbuf),
                     plaintext, sizeof(plaintext)))
        goto cleanup;

    ok = 1;                                       /* all checks passed */

cleanup:
    BIO_free_all(enc_filter);   /* also frees enc_sink */
    BIO_free_all(dec_filter);   /* also frees dec_src */
    return ok;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
