/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p4_tp1_s6_260827_125305.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    /* Fixed key and IV for AES‑256‑CBC */
    unsigned char key[32];
    unsigned char iv[16];
    size_t i;

    for (i = 0; i < sizeof(key); i++)
        key[i] = (unsigned char)i;
    for (i = 0; i < sizeof(iv); i++)
        iv[i] = (unsigned char)(0xA0 + i);

    /* Plain‑text to encrypt/decrypt */
    const char plaintext[] = "OpenSSL BIO cipher round‑trip test vector";
    const size_t pt_len = sizeof(plaintext) - 1; /* omit trailing NUL */

    /* ---------- Encryption side ---------- */
    BIO *mem_enc = BIO_new(BIO_s_mem());
    if (!TEST_ptr(mem_enc))
        return 0;

    BIO *enc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(enc)) {
        BIO_free(mem_enc);
        return 0;
    }

    if (!TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                 key, iv, 1))) {
        BIO_free_all(enc);
        BIO_free(mem_enc);
        return 0;
    }

    BIO_push(enc, mem_enc);

    if (!TEST_int_eq(BIO_write(enc, plaintext, (int)pt_len), (int)pt_len)) {
        BIO_free_all(enc);
        return 0;
    }
    if (!TEST_true(BIO_flush(enc))) {
        BIO_free_all(enc);
        return 0;
    }

    /* Retrieve encrypted bytes */
    char *enc_data = NULL;
    long enc_len = BIO_get_mem_data(mem_enc, &enc_data);
    if (!TEST_int_gt(enc_len, 0)) {
        BIO_free_all(enc);
        return 0;
    }

    /* ---------- Decryption side ---------- */
    BIO *mem_dec = BIO_new_mem_buf(enc_data, (int)enc_len);
    if (!TEST_ptr(mem_dec)) {
        BIO_free_all(enc);
        return 0;
    }

    BIO *dec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(dec)) {
        BIO_free(mem_dec);
        BIO_free_all(enc);
        return 0;
    }

    if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                 key, iv, 0))) {
        BIO_free_all(dec);
        BIO_free(mem_dec);
        BIO_free_all(enc);
        return 0;
    }

    BIO_push(dec, mem_dec);

    unsigned char outbuf[256];
    int outlen = BIO_read(dec, outbuf, sizeof(outbuf));
    if (!TEST_int_gt(outlen, 0)) {
        BIO_free_all(dec);
        BIO_free_all(enc);
        return 0;
    }
    if (!TEST_int_eq(outlen, (int)pt_len)) {
        BIO_free_all(dec);
        BIO_free_all(enc);
        return 0;
    }
    if (!TEST_mem_eq(outbuf, outlen, plaintext, pt_len)) {
        BIO_free_all(dec);
        BIO_free_all(enc);
        return 0;
    }

    /* Clean up */
    BIO_free_all(dec);
    BIO_free_all(enc);
    return 1;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
