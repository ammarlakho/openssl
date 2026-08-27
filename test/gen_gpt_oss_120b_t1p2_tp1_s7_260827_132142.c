/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t1p2_tp1_s7_260827_132142.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    /* Test vector */
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
    static const unsigned char plaintext[] =
        "OpenSSL BIO AES-256-CBC test vector 12345";

    const int plen = sizeof(plaintext) - 1; /* no trailing NUL */
    unsigned char evp_ct[128];
    int evp_out1 = 0, evp_out2 = 0, evp_ct_len = 0;
    EVP_CIPHER_CTX *evp_ctx = NULL;

    /* ------------------------------------------------------------
     * Compute expected ciphertext using the EVP API (non‑BIO)
     * ------------------------------------------------------------ */
    evp_ctx = EVP_CIPHER_CTX_new();
    if (!TEST_ptr(evp_ctx))
        return 0;

    if (!TEST_int_eq(EVP_EncryptInit_ex(evp_ctx,
                     EVP_aes_256_cbc(), NULL, key, iv), 1))
        return 0;

    if (!TEST_int_eq(EVP_EncryptUpdate(evp_ctx,
                     evp_ct, &evp_out1,
                     plaintext, plen), 1))
        return 0;

    if (!TEST_int_eq(EVP_EncryptFinal_ex(evp_ctx,
                     evp_ct + evp_out1, &evp_out2), 1))
        return 0;

    evp_ct_len = evp_out1 + evp_out2;
    EVP_CIPHER_CTX_free(evp_ctx);
    evp_ctx = NULL;

    /* ------------------------------------------------------------
     * Encrypt via BIO_f_cipher and compare with EVP result
     * ------------------------------------------------------------ */
    BIO *bmem_enc = BIO_new(BIO_s_mem());
    BIO *bciph_enc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bmem_enc) || !TEST_ptr(bciph_enc))
        return 0;

    if (!TEST_int_eq(BIO_set_cipher(bciph_enc,
                     EVP_aes_256_cbc(), key, iv, 1), 1))
        return 0;

    BIO_push(bciph_enc, bmem_enc);

    if (!TEST_int_eq(BIO_write(bciph_enc, plaintext, plen), plen))
        return 0;

    if (!TEST_int_eq(BIO_flush(bciph_enc), 1))
        return 0;

    /* extract ciphertext from the memory BIO */
    char *bio_ct = NULL;
    long bio_ct_len = BIO_get_mem_data(bmem_enc, &bio_ct);
    if (!TEST_int_gt(bio_ct_len, 0))
        return 0;
    if (!TEST_int_eq((int)bio_ct_len, evp_ct_len))
        return 0;
    if (!TEST_mem_eq(bio_ct, (size_t)bio_ct_len,
                     evp_ct, (size_t)evp_ct_len))
        return 0;

    BIO_free_all(bciph_enc); /* also frees bmem_enc */

    /* ------------------------------------------------------------
     * Decrypt via BIO_f_cipher and verify we obtain original plain
     * ------------------------------------------------------------ */
    BIO *bmem_dec = BIO_new_mem_buf(bio_ct, (int)bio_ct_len);
    BIO *bciph_dec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bmem_dec) || !TEST_ptr(bciph_dec))
        return 0;

    if (!TEST_int_eq(BIO_set_cipher(bciph_dec,
                     EVP_aes_256_cbc(), key, iv, 0), 1))
        return 0;

    BIO_push(bciph_dec, bmem_dec);

    unsigned char dec_buf[256];
    int dec_total = 0, dec_now = 0;
    while ((dec_now = BIO_read(bciph_dec,
                               dec_buf + dec_total,
                               (int)sizeof(dec_buf) - dec_total)) > 0) {
        dec_total += dec_now;
        if (dec_total >= plen)
            break;
    }

    if (!TEST_int_eq(dec_total, plen))
        return 0;
    if (!TEST_mem_eq(dec_buf, (size_t)dec_total,
                     plaintext, (size_t)plen))
        return 0;

    BIO_free_all(bciph_dec); /* also frees bmem_dec */

    return 1;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
