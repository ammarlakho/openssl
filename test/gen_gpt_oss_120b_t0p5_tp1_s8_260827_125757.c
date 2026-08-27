/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p5_tp1_s8_260827_125757.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    int ok = 1;
    const unsigned char key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    const unsigned char iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    const unsigned char plaintext[] = "OpenSSL BIO Cipher Test Vector";
    const int pt_len = (int)strlen((const char *)plaintext);

    /* -----------------------------------------------------------------
     * 1. Produce reference ciphertext using the EVP API.
     * ----------------------------------------------------------------- */
    unsigned char ref_ct[256];
    int ref_ct_len = 0, outlen = 0;
    EVP_CIPHER_CTX *ref_ctx = EVP_CIPHER_CTX_new();

    if (!TEST_ptr(ref_ctx))
        return 0;

    if (!TEST_true(EVP_CipherInit_ex(ref_ctx, EVP_aes_256_cbc(),
                                    NULL, key, iv, 1)))
        ok = 0;
    if (!TEST_true(EVP_CipherUpdate(ref_ctx, ref_ct, &outlen,
                                    plaintext, pt_len)))
        ok = 0;
    ref_ct_len = outlen;
    if (!TEST_true(EVP_CipherFinal_ex(ref_ctx, ref_ct + ref_ct_len, &outlen)))
        ok = 0;
    ref_ct_len += outlen;
    EVP_CIPHER_CTX_free(ref_ctx);

    /* -----------------------------------------------------------------
     * 2. Encrypt using BIO_f_cipher and compare with reference.
     * ----------------------------------------------------------------- */
    BIO *mem_enc = BIO_new(BIO_s_mem());
    BIO *bio_enc = BIO_new(BIO_f_cipher());

    if (!TEST_ptr(mem_enc) || !TEST_ptr(bio_enc))
        return 0;

    if (!TEST_true(BIO_set_cipher(bio_enc, EVP_aes_256_cbc(),
                                 key, iv, 1))) /* encrypt */
        ok = 0;

    BIO_push(bio_enc, mem_enc);

    if (!TEST_int_eq(BIO_write(bio_enc, plaintext, pt_len), pt_len))
        ok = 0;
    if (!TEST_true(BIO_flush(bio_enc)))
        ok = 0;

    unsigned char bio_ct[256];
    int bio_ct_len = BIO_read(mem_enc, bio_ct, sizeof(bio_ct));
    if (!TEST_int_eq(bio_ct_len, ref_ct_len))
        ok = 0;
    if (!TEST_mem_eq(bio_ct, bio_ct_len, ref_ct, ref_ct_len))
        ok = 0;

    BIO_free_all(bio_enc); /* also frees mem_enc */

    /* -----------------------------------------------------------------
     * 3. Decrypt the ciphertext using BIO_f_cipher and verify plaintext.
     * ----------------------------------------------------------------- */
    BIO *mem_dec = BIO_new_mem_buf(bio_ct, bio_ct_len);
    BIO *bio_dec = BIO_new(BIO_f_cipher());

    if (!TEST_ptr(mem_dec) || !TEST_ptr(bio_dec))
        return 0;

    if (!TEST_true(BIO_set_cipher(bio_dec, EVP_aes_256_cbc(),
                                 key, iv, 0))) /* decrypt */
        ok = 0;

    BIO_push(bio_dec, mem_dec);

    unsigned char outbuf[256];
    int out_len = BIO_read(bio_dec, outbuf, sizeof(outbuf));
    if (!TEST_int_eq(out_len, pt_len))
        ok = 0;
    if (!TEST_mem_eq(outbuf, out_len, plaintext, pt_len))
        ok = 0;

    BIO_free_all(bio_dec); /* also frees mem_dec */

    return ok;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
