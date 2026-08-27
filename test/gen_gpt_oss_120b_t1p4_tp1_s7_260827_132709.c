/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t1p4_tp1_s7_260827_132709.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    int ok = 1;
    const unsigned char key[32] = {0};
    const unsigned char iv[16] = {0};

    /* Plaintext test vector (not a multiple of block size) */
    const unsigned char plaintext[] = "The quick brown fox jumps over the lazy dog";
    const size_t plain_len = sizeof(plaintext) - 1; /* exclude NUL */

    /* -----------------------------------------------------------------
     * 1. Produce the reference ciphertext using the low‑level EVP API.
     * ----------------------------------------------------------------- */
    unsigned char ref_ct[128];
    int ref_ct_len = 0;
    EVP_CIPHER_CTX *evp_ctx = EVP_CIPHER_CTX_new();

    ok &= TEST_ptr(evp_ctx);
    if (!ok) return 0;

    ok &= TEST_true(EVP_EncryptInit_ex(evp_ctx, EVP_aes_256_cbc(),
                                      NULL, key, iv));
    if (!ok) {
        EVP_CIPHER_CTX_free(evp_ctx);
        return 0;
    }

    {
        int outlen = 0;
        ok &= TEST_true(EVP_EncryptUpdate(evp_ctx,
                                          ref_ct, &outlen,
                                          plaintext, (int)plain_len));
        if (!ok) {
            EVP_CIPHER_CTX_free(evp_ctx);
            return 0;
        }
        ref_ct_len = outlen;
    }

    {
        int outlen = 0;
        ok &= TEST_true(EVP_EncryptFinal_ex(evp_ctx,
                                            ref_ct + ref_ct_len, &outlen));
        if (!ok) {
            EVP_CIPHER_CTX_free(evp_ctx);
            return 0;
        }
        ref_ct_len += outlen;
    }
    EVP_CIPHER_CTX_free(evp_ctx);

    /* -----------------------------------------------------------------
     * 2. Encrypt via the cipher BIO and compare with the reference
     *    ciphertext.
     * ----------------------------------------------------------------- */
    BIO *mem_enc = BIO_new(BIO_s_mem());
    BIO *benc    = BIO_new(BIO_f_cipher());

    ok &= TEST_ptr(mem_enc);
    ok &= TEST_ptr(benc);
    if (!ok) {
        BIO_free_all(benc);
        BIO_free(mem_enc);
        return 0;
    }

    ok &= TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(),
                                  key, iv, 1));               /* encrypt */
    if (!ok) {
        BIO_free_all(benc);
        BIO_free(mem_enc);
        return 0;
    }

    BIO_push(benc, mem_enc);

    ok &= TEST_int_eq(BIO_write(benc, plaintext, (int)plain_len), (int)plain_len);
    ok &= TEST_int_gt(BIO_flush(benc), 0);

    /* Retrieve ciphertext from the underlying memory BIO */
    BUF_MEM *bptr = NULL;
    BIO_get_mem_ptr(mem_enc, &bptr);
    ok &= TEST_ptr(bptr);
    ok &= TEST_int_eq((int)bptr->length, ref_ct_len);
    ok &= TEST_mem_eq(bptr->data, bptr->length, ref_ct, ref_ct_len);

    /* Keep a local copy before freeing the BIO chain */
    unsigned char ct_copy[128];
    size_t ct_len = 0;
    if (ok) {
        memcpy(ct_copy, bptr->data, bptr->length);
        ct_len = bptr->length;
    }

    BIO_free_all(benc);            /* also frees mem_enc */

    /* -----------------------------------------------------------------
     * 3. Decrypt the ciphertext via a cipher BIO and verify we obtain
     *    the original plaintext.
     * ----------------------------------------------------------------- */
    BIO *mem_dec = BIO_new_mem_buf(ct_copy, (int)ct_len);
    BIO *bdec    = BIO_new(BIO_f_cipher());

    ok &= TEST_ptr(mem_dec);
    ok &= TEST_ptr(bdec);
    if (!ok) {
        BIO_free_all(bdec);
        BIO_free(mem_dec);
        return 0;
    }

    ok &= TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(),
                                  key, iv, 0));               /* decrypt */
    if (!ok) {
        BIO_free_all(bdec);
        BIO_free(mem_dec);
        return 0;
    }

    BIO_push(bdec, mem_dec);

    unsigned char outbuf[128];
    int out_len = 0, ret;

    /* Read until the BIO reports no more data */
    while ((ret = BIO_read(bdec, outbuf + out_len,
                          (int)(sizeof(outbuf) - out_len))) > 0) {
        out_len += ret;
    }
    ok &= TEST_int_ge(ret, 0);                 /* either 0 (EOF) or >0 */

    ok &= TEST_int_eq(out_len, (int)plain_len);
    ok &= TEST_mem_eq(outbuf, out_len, plaintext, plain_len);

    BIO_free_all(bdec);          /* also frees mem_dec */

    return ok ? 1 : 0;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
