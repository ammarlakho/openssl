/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p5_tp1_s3_260827_125558.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    /* Test AES‑256‑CBC BIO encrypt → decrypt round‑trip */
    const unsigned char key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    const unsigned char iv[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    const unsigned char plaintext[] =
        "OpenSSL BIO cipher test vector data.";
    const int pt_len = (int)sizeof(plaintext) - 1; /* no NUL */
    BIO *enc = NULL, *enc_sink = NULL;
    BIO *dec = NULL, *dec_src = NULL;
    char *cipherdata = NULL;
    long cipherlen = 0;
    unsigned char outbuf[256];
    int outlen = 0, r, ret = 0;

    /* ---------- encryption ---------- */
    enc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(enc))
        goto end;
    if (!TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                 key, iv, 1)))   /* encrypt */
        goto end;

    enc_sink = BIO_new(BIO_s_mem());
    if (!TEST_ptr(enc_sink))
        goto end;
    BIO_push(enc, enc_sink);

    r = BIO_write(enc, plaintext, pt_len);
    if (!TEST_int_eq(r, pt_len))
        goto end;

    /* flush to force final block */
    if (!TEST_int_eq(BIO_ctrl(enc, BIO_CTRL_FLUSH, 0, NULL), 1))
        goto end;

    if (!TEST_int_gt(BIO_get_mem_data(enc_sink, &cipherdata), 0))
        goto end;
    cipherlen = BIO_get_mem_data(enc_sink, &cipherdata);
    if (!TEST_int_gt(cipherlen, 0))
        goto end;

    /* ---------- decryption ---------- */
    dec_src = BIO_new_mem_buf(cipherdata, (int)cipherlen);
    if (!TEST_ptr(dec_src))
        goto end;

    dec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(dec))
        goto end;
    if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                 key, iv, 0)))   /* decrypt */
        goto end;
    BIO_push(dec, dec_src);

    outlen = 0;
    for (;;) {
        r = BIO_read(dec, outbuf + outlen, sizeof(outbuf) - outlen);
        if (r > 0) {
            outlen += r;
            continue;
        }
        if (r == 0)
            break;
        if (BIO_should_retry(dec))
            continue;
        /* error */
        goto end;
    }

    if (!TEST_int_eq(outlen, pt_len))
        goto end;
    if (!TEST_mem_eq(outbuf, outlen, plaintext, pt_len))
        goto end;

    /* success */
    ret = 1;

end:
    BIO_free_all(enc);
    BIO_free_all(dec);
    BIO_free(enc_sink);
    BIO_free(dec_src);
    return ret;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
