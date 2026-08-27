/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t1p2_tp1_s1_260827_131840.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    /* Key, IV and plaintext for the test */
    unsigned char key[32] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
        0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };
    unsigned char iv[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    unsigned char plaintext[] =
        "The quick brown fox jumps over the lazy dog";
    size_t pl_len = sizeof(plaintext) - 1; /* exclude NUL */

    /* -----------------------------------------------------------------
     * 1. Produce the expected ciphertext with the EVP API (direct mode).
     * ----------------------------------------------------------------- */
    EVP_CIPHER_CTX *evp_ctx = NULL;
    unsigned char evp_ct[64];
    int evp_outlen = 0, evp_flen = 0, evp_total = 0;

    evp_ctx = EVP_CIPHER_CTX_new();
    if (!TEST_ptr(evp_ctx))
        return 0;
    if (!TEST_true(EVP_EncryptInit_ex(evp_ctx, EVP_aes_256_cbc(),
                                      NULL, key, iv)))
        goto err;
    if (!TEST_true(EVP_EncryptUpdate(evp_ctx, evp_ct, &evp_outlen,
                                     plaintext, (int)pl_len)))
        goto err;
    evp_total = evp_outlen;
    if (!TEST_true(EVP_EncryptFinal_ex(evp_ctx,
                                       evp_ct + evp_total, &evp_flen)))
        goto err;
    evp_total += evp_flen; /* evp_total now holds ciphertext length */

    /* -----------------------------------------------------------------
     * 2. Encrypt using BIO_f_cipher and compare with the EVP result.
     * ----------------------------------------------------------------- */
    BIO *b64_enc = NULL, *bmem_enc = NULL;
    unsigned char *bio_enc_data = NULL;
    long bio_enc_len = 0;
    int ret;

    bmem_enc = BIO_new(BIO_s_mem());
    if (!TEST_ptr(bmem_enc))
        goto err;
    b64_enc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(b64_enc))
        goto err;
    if (!TEST_true(BIO_set_cipher(b64_enc, EVP_aes_256_cbc(),
                                  key, iv, 1)))   /* encrypt */
        goto err;
    BIO_push(b64_enc, bmem_enc);

    ret = BIO_write(b64_enc, plaintext, (int)pl_len);
    if (!TEST_int_eq(ret, (int)pl_len))
        goto err;
    /* Flush to force final block processing */
    if (!TEST_int_gt(BIO_flush(b64_enc), 0))
        goto err;

    /* Retrieve encrypted data from the memory BIO */
    BIO_get_mem_data(bmem_enc, &bio_enc_data);
    bio_enc_len = BIO_get_mem_data(bmem_enc, &bio_enc_data);
    if (!TEST_int_eq((int)bio_enc_len, evp_total))
        goto err;
    if (!TEST_mem_eq(bio_enc_data, bio_enc_len,
                     evp_ct, evp_total))
        goto err;

    /* -----------------------------------------------------------------
     * 3. Decrypt the BIO‑produced ciphertext and verify we obtain the
     *    original plaintext.
     * ----------------------------------------------------------------- */
    BIO *bmem_dec = NULL, *bdec = NULL;
    unsigned char dec_out[64];
    int dec_len = 0, dec_flen = 0, dec_total = 0;

    bmem_dec = BIO_new_mem_buf(bio_enc_data,
                               (int)bio_enc_len);
    if (!TEST_ptr(bmem_dec))
        goto err;
    bdec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bdec))
        goto err;
    if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(),
                                  key, iv, 0)))   /* decrypt */
        goto err;
    BIO_push(bdec, bmem_dec);

    ret = BIO_read(bdec, dec_out, sizeof(dec_out));
    if (!TEST_int_gt(ret, 0))
        goto err;
    dec_len = ret;
    /* Attempt to read any remaining data (should be none) */
    while ((ret = BIO_read(bdec, dec_out + dec_len,
                          (int)sizeof(dec_out) - dec_len)) > 0) {
        dec_len += ret;
    }
    /* Finalise any pending decryption */
    BIO_ctrl(bdec, BIO_CTRL_FLUSH, 0, NULL);
    dec_total = dec_len;

    if (!TEST_int_eq(dec_total, (int)pl_len))
        goto err;
    if (!TEST_mem_eq(dec_out, dec_total,
                     plaintext, pl_len))
        goto err;

    /* Success */
    BIO_free_all(b64_enc);
    BIO_free_all(bdec);
    EVP_CIPHER_CTX_free(evp_ctx);
    return 1;

err:
    BIO_free_all(b64_enc);
    BIO_free_all(bdec);
    EVP_CIPHER_CTX_free(evp_ctx);
    return 0;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
