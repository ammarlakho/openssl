/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p5_tp1_s7_260827_125738.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    /* Test AES‑256‑CBC encryption/decryption using BIO_f_cipher */
    const unsigned char key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    const unsigned char iv[16] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf
    };
    const unsigned char plaintext[] =
        "OpenSSL test vector for AES-256 CBC mode.";
    const int pt_len = (int)sizeof(plaintext) - 1; /* exclude NUL */
    unsigned char outbuf[256];
    int ok = 1;
    BIO *mem = NULL, *enc = NULL, *dec = NULL, *src = NULL;
    char *cipherdata = NULL;
    long cipherlen = 0;
    int outlen = 0;

    /* ---------- encrypt ---------- */
    mem = BIO_new(BIO_s_mem());
    enc = BIO_new(BIO_f_cipher());
    ok = ok && TEST_ptr(mem) && TEST_ptr(enc);
    if (!ok) goto err;

    ok = ok && TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                        key, iv, 1)); /* encrypt */
    if (!ok) goto err;

    /* push the memory BIO underneath the cipher BIO */
    BIO_push(enc, mem);

    ok = ok && TEST_int_eq(BIO_write(enc, plaintext, pt_len), pt_len);
    ok = ok && TEST_int_eq(BIO_flush(enc), 1);
    if (!ok) goto err;

    cipherlen = BIO_get_mem_data(mem, &cipherdata);
    ok = ok && TEST_int_gt(cipherlen, pt_len); /* ciphertext should be longer */
    if (!ok) goto err;

    /* ---------- decrypt ---------- */
    src = BIO_new_mem_buf(cipherdata, (int)cipherlen);
    dec = BIO_new(BIO_f_cipher());
    ok = ok && TEST_ptr(src) && TEST_ptr(dec);
    if (!ok) goto err;

    ok = ok && TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                        key, iv, 0)); /* decrypt */
    if (!ok) goto err;

    BIO_push(dec, src);

    outlen = BIO_read(dec, outbuf, sizeof(outbuf));
    ok = ok && TEST_int_eq(outlen, pt_len);
    ok = ok && TEST_mem_eq(outbuf, pt_len, plaintext, pt_len);
    if (!ok) goto err;

 err:
    BIO_free_all(enc);
    BIO_free_all(dec);
    /* mem and src are freed by the above BIO_free_all calls */
    return ok;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
