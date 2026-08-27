/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p2_tp0p95_fp0_s1_260827_002233.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    /* Test vectors */
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
        "The quick brown fox jumps over the lazy dog";
    const int pt_len = (int)sizeof(plaintext) - 1; /* no NUL */

    unsigned char *expected_ct = NULL;
    int expected_ct_len = 0;
    EVP_CIPHER_CTX *cctx = NULL;
    int outlen, tmplen;
    int ret = 0; /* failure until all checks succeed */

    /* -----------------------------------------------------------------
     * 1. Produce expected ciphertext using the EVP API (reference)
     * ----------------------------------------------------------------- */
    cctx = EVP_CIPHER_CTX_new();
    if (!TEST_ptr(cctx))
        goto end;
    if (!TEST_true(EVP_EncryptInit_ex(cctx, EVP_aes_256_cbc(),
                                      NULL, key, iv)))
        goto end;

    expected_ct = OPENSSL_malloc(pt_len + EVP_MAX_BLOCK_LENGTH);
    if (!TEST_ptr(expected_ct))
        goto end;

    if (!TEST_true(EVP_EncryptUpdate(cctx, expected_ct, &outlen,
                                     plaintext, pt_len)))
        goto end;
    expected_ct_len = outlen;

    if (!TEST_true(EVP_EncryptFinal_ex(cctx, expected_ct + outlen, &tmplen)))
        goto end;
    expected_ct_len += tmplen;

    EVP_CIPHER_CTX_free(cctx);
    cctx = NULL;

    /* -----------------------------------------------------------------
     * 2. Encrypt via BIO_f_cipher and compare with reference ciphertext
     * ----------------------------------------------------------------- */
    {
        BIO *mem = BIO_new(BIO_s_mem());
        BIO *cipher = BIO_new(BIO_f_cipher());

        if (!TEST_ptr(mem) || !TEST_ptr(cipher))
            goto end;

        if (!TEST_true(BIO_set_cipher(cipher, EVP_aes_256_cbc(),
                                      key, iv, 1)))
            goto end;

        BIO_push(cipher, mem);

        if (!TEST_int_eq(BIO_write(cipher, plaintext, pt_len), pt_len))
            goto end;
        if (!TEST_true(BIO_flush(cipher)))
            goto end;

        /* Retrieve encrypted data from the underlying memory BIO */
        char *enc_data = NULL;
        long enc_len = BIO_get_mem_data(mem, &enc_data);
        if (!TEST_int_eq((int)enc_len, expected_ct_len))
            goto end;
        if (!TEST_mem_eq(enc_data, (size_t)enc_len,
                         expected_ct, (size_t)expected_ct_len))
            goto end;

        BIO_free_all(cipher); /* also frees mem */
    }

    /* -----------------------------------------------------------------
     * 3. Decrypt via BIO_f_cipher and verify we obtain the original text
     * ----------------------------------------------------------------- */
    {
        BIO *mem = BIO_new_mem_buf(expected_ct, expected_ct_len);
        BIO *dec = BIO_new(BIO_f_cipher());

        if (!TEST_ptr(mem) || !TEST_ptr(dec))
            goto end;

        if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                      key, iv, 0)))
            goto end;

        BIO_push(dec, mem);

        unsigned char *outbuf = OPENSSL_malloc(expected_ct_len);
        if (!TEST_ptr(outbuf))
            goto end;

        int read_len = BIO_read(dec, outbuf, expected_ct_len);
        if (!TEST_int_gt(read_len, 0))
            goto free_out;
        if (!TEST_int_eq(read_len, pt_len))
            goto free_out;
        if (!TEST_mem_eq(outbuf, (size_t)read_len,
                         plaintext, (size_t)pt_len))
            goto free_out;

        ret = 1; /* all checks passed */

    free_out:
        OPENSSL_free(outbuf);
        BIO_free_all(dec); /* also frees mem */
    }

end:
    if (cctx)
        EVP_CIPHER_CTX_free(cctx);
    OPENSSL_free(expected_ct);
    return ret;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
