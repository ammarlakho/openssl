/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p5_tp1_s10_260827_125853.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    /* Test vector (AES‑256‑CBC, no padding) */
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
    static const unsigned char pt[16] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
    };
    static const unsigned char ct_expected[16] = {
        0xf5,0x8c,0x4c,0x04,0xd6,0xe5,0xf1,0xba,
        0x77,0x9e,0xab,0xfb,0x5f,0x7b,0xfb,0xd6
    };

    BIO *mem = NULL, *enc = NULL, *dec = NULL, *src = NULL;
    EVP_CIPHER_CTX *cctx = NULL;
    const char *out_data = NULL;
    long out_len = 0;
    unsigned char out_buf[sizeof(pt)];
    int ret = 0, w, r;

    /* ---------- Encryption ---------- */
    mem = BIO_new(BIO_s_mem());
    if (!TEST_ptr(mem))
        goto end;

    enc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(enc))
        goto end;

    if (!TEST_int_eq(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                   key, iv, 1), 1))
        goto end;

    /* Disable padding so the ciphertext matches the raw test vector */
    if (!TEST_int_eq(BIO_ctrl(enc, BIO_C_GET_CIPHER_CTX, 0, &cctx), 1))
        goto end;
    if (!TEST_true(EVP_CIPHER_CTX_set_padding(cctx, 0)))
        goto end;

    BIO_push(enc, mem);

    w = BIO_write(enc, pt, sizeof(pt));
    if (!TEST_int_eq(w, (int)sizeof(pt)))
        goto end;

    if (!TEST_true(BIO_flush(enc)))
        goto end;

    out_len = BIO_get_mem_data(mem, &out_data);
    if (!TEST_long_eq(out_len, (long)sizeof(ct_expected)))
        goto end;
    if (!TEST_mem_eq(out_data, out_len, ct_expected, sizeof(ct_expected)))
        goto end;

    /* ---------- Decryption ---------- */
    src = BIO_new_mem_buf(out_data, out_len);
    if (!TEST_ptr(src))
        goto end;

    dec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(dec))
        goto end;

    if (!TEST_int_eq(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                   key, iv, 0), 1))
        goto end;

    if (!TEST_int_eq(BIO_ctrl(dec, BIO_C_GET_CIPHER_CTX, 0, &cctx), 1))
        goto end;
    if (!TEST_true(EVP_CIPHER_CTX_set_padding(cctx, 0)))
        goto end;

    BIO_push(dec, src);

    r = BIO_read(dec, out_buf, sizeof(out_buf));
    if (!TEST_int_eq(r, (int)sizeof(pt)))
        goto end;
    if (!TEST_mem_eq(out_buf, sizeof(out_buf), pt, sizeof(pt)))
        goto end;

    ret = 1;   /* success */

end:
    BIO_free_all(enc);
    BIO_free_all(dec);
    BIO_free_all(mem);
    BIO_free_all(src);
    return ret;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
