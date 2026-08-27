/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p3_tp1_s4_260827_124814.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    /* Test vector – all‑zero key/IV, simple plaintext */
    static const unsigned char key[32] = {0};
    static const unsigned char iv[16]  = {0};
    static const unsigned char plaintext[] = "OpenSSL BIO cipher test vector";
    const int pt_len = (int)sizeof(plaintext) - 1; /* exclude NUL */

    BIO *enc_mem = NULL, *enc_bio = NULL;
    BIO *dec_mem = NULL, *dec_bio = NULL;
    unsigned char *enc_ptr = NULL;
    long enc_len = 0;
    int ret = 0;

    /* ---------- Encryption ---------- */
    enc_mem = BIO_new(BIO_s_mem());
    if (!TEST_ptr(enc_mem))
        goto end;

    enc_bio = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(enc_bio))
        goto end;

    if (!TEST_true(BIO_set_cipher(enc_bio, EVP_aes_256_cbc(),
                                 key, iv, 1)))   /* encrypt = 1 */
        goto end;

    BIO_push(enc_bio, enc_mem);

    if (!TEST_int_eq(BIO_write(enc_bio, plaintext, pt_len), pt_len))
        goto end;

    if (!TEST_true(BIO_flush(enc_bio)))
        goto end;

    enc_len = BIO_get_mem_data(enc_mem, &enc_ptr);
    if (!TEST_long_gt(enc_len, 0))
        goto end;

    /* ---------- Decryption ---------- */
    dec_mem = BIO_new_mem_buf(enc_ptr, (int)enc_len);
    if (!TEST_ptr(dec_mem))
        goto end;

    dec_bio = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(dec_bio))
        goto end;

    if (!TEST_true(BIO_set_cipher(dec_bio, EVP_aes_256_cbc(),
                                 key, iv, 0)))   /* encrypt = 0 (decrypt) */
        goto end;

    BIO_push(dec_bio, dec_mem);

    unsigned char outbuf[256];
    int outlen = BIO_read(dec_bio, outbuf, sizeof(outbuf));
    if (!TEST_int_gt(outlen, 0))
        goto end;

    if (!TEST_mem_eq(outbuf, outlen, plaintext, pt_len))
        goto end;

    /* Verify that the cipher reported success */
    if (!TEST_long_eq(BIO_ctrl(dec_bio, BIO_C_GET_CIPHER_STATUS, 0, NULL), 1))
        goto end;

    ret = 1;   /* all checks passed */

end:
    BIO_free_all(enc_bio);   /* also frees enc_mem */
    BIO_free_all(dec_bio);   /* also frees dec_mem */
    return ret;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
