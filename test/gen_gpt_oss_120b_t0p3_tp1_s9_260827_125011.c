/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p3_tp1_s9_260827_125011.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    /* Test vector: simple plaintext, zero key/IV for reproducibility */
    const unsigned char key[32] = {0};
    const unsigned char iv[16]  = {0};
    const unsigned char plaintext[] =
        "The quick brown fox jumps over the lazy dog";
    const int plen = (int)sizeof(plaintext) - 1; /* exclude terminating NUL */

    BIO *mem = NULL;          /* memory BIO for ciphertext */
    BIO *enc = NULL;          /* encryption filter BIO */
    BIO *mem_in = NULL;       /* memory BIO holding ciphertext for decryption */
    BIO *dec = NULL;          /* decryption filter BIO */
    char *enc_data = NULL;    /* pointer to ciphertext inside mem */
    long enc_len = 0;
    unsigned char out[128];   /* buffer for decrypted data */
    EVP_CIPHER_CTX *cctx = NULL;
    int ret = 0;
    int i;

    /* ---------- Encryption ---------- */
    if (!TEST_ptr(mem = BIO_new(BIO_s_mem())))
        goto end;
    if (!TEST_ptr(enc = BIO_new(BIO_f_cipher())))
        goto end;
    if (!TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                 key, iv, 1)))   /* 1 = encrypt */
        goto end;

    BIO_push(enc, mem);
    i = BIO_write(enc, plaintext, plen);
    if (!TEST_int_eq(i, plen))
        goto end;
    if (!TEST_true(BIO_flush(enc)))
        goto end;

    enc_len = BIO_get_mem_data(mem, &enc_data);
    if (!TEST_int_gt(enc_len, 0))
        goto end;

    /* ---------- Decryption ---------- */
    if (!TEST_ptr(mem_in = BIO_new_mem_buf(enc_data, (int)enc_len)))
        goto end;
    if (!TEST_ptr(dec = BIO_new(BIO_f_cipher())))
        goto end;
    if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                 key, iv, 0)))   /* 0 = decrypt */
        goto end;

    BIO_push(dec, mem_in);
    i = BIO_read(dec, out, sizeof(out));
    if (!TEST_int_eq(i, plen))
        goto end;
    if (!TEST_mem_eq(out, plen, plaintext, plen))
        goto end;

    /* ---------- Additional checks ---------- */
    if (!TEST_int_eq(BIO_ctrl(dec, BIO_C_GET_CIPHER_STATUS, 0, NULL), 1))
        goto end;

    if (!TEST_true(BIO_ctrl(dec, BIO_C_GET_CIPHER_CTX, 0, &cctx)))
        goto end;
    if (!TEST_ptr(cctx))
        goto end;

    ret = 1;   /* success */

end:
    BIO_free_all(enc);   /* also frees mem */
    BIO_free_all(dec);   /* also frees mem_in */
    return ret;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
