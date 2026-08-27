/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t1_tp1_s10_260827_131801.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    /* AES‑256‑CBC test vector (key/IV) */
    const unsigned char key[32] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
        0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };
    const unsigned char iv[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    const unsigned char plaintext[] =
        "The quick brown fox jumps over the lazy dog";
    int plen = (int)strlen((const char *)plaintext);

    /* -----------------------------------------------------------------
     * Produce the reference ciphertext using the EVP API directly.
     * ----------------------------------------------------------------- */
    unsigned char ref_ct[256];
    int ref_len = 0, ref_fin = 0;
    EVP_CIPHER_CTX *evp = EVP_CIPHER_CTX_new();
    if (!TEST_ptr(evp))
        return 0;
    if (!TEST_int_eq(EVP_EncryptInit_ex(evp, EVP_aes_256_cbc(),
                                      NULL, key, iv), 1))
        goto err_evp;
    if (!TEST_int_eq(EVP_EncryptUpdate(evp, ref_ct, &ref_len,
                                      plaintext, plen), 1))
        goto err_evp;
    if (!TEST_int_eq(EVP_EncryptFinal_ex(evp, ref_ct + ref_len, &ref_fin), 1))
        goto err_evp;
    ref_len += ref_fin;
    EVP_CIPHER_CTX_free(evp);
    evp = NULL;

    /* -----------------------------------------------------------------
     * Encrypt via BIO_f_cipher and compare with the reference ciphertext.
     * ----------------------------------------------------------------- */
    BIO *mem = BIO_new(BIO_s_mem());
    BIO *enc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(mem) || !TEST_ptr(enc))
        goto err_cleanup;
    if (!TEST_int_eq(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                   key, iv, 1), 1))
        goto err_cleanup;
    BIO_push(enc, mem);

    if (!TEST_int_eq(BIO_write(enc, plaintext, plen), plen))
        goto err_cleanup;
    if (!TEST_int_eq(BIO_flush(enc), 1))
        goto err_cleanup;

    char *enc_data = NULL;
    long enc_len = BIO_get_mem_data(mem, &enc_data);
    if (!TEST_int_eq((int)enc_len, ref_len))
        goto err_cleanup;
    if (!TEST_mem_eq(enc_data, (size_t)enc_len,
                     ref_ct, (size_t)ref_len))
        goto err_cleanup;

    BIO_free_all(enc);   /* also frees mem */

    /* -----------------------------------------------------------------
     * Decrypt the ciphertext via BIO_f_cipher and verify we recover plaintext.
     * ----------------------------------------------------------------- */
    BIO *src = BIO_new_mem_buf(ref_ct, ref_len);
    BIO *dec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(src) || !TEST_ptr(dec))
        goto err_cleanup2;
    if (!TEST_int_eq(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                   key, iv, 0), 1))
        goto err_cleanup2;
    BIO_push(dec, src);

    unsigned char outbuf[256];
    int outlen = 0, r;
    while ((r = BIO_read(dec, outbuf + outlen,
                        sizeof(outbuf) - outlen)) > 0) {
        outlen += r;
    }
    if (!TEST_int_eq(outlen, plen))
        goto err_cleanup2;
    if (!TEST_mem_eq(outbuf, (size_t)outlen,
                     plaintext, (size_t)plen))
        goto err_cleanup2;

    BIO_free_all(dec);
    return 1;

err_evp:
    EVP_CIPHER_CTX_free(evp);
err_cleanup:
    BIO_free_all(enc);
    BIO_free_all(mem);
    return 0;
err_cleanup2:
    BIO_free_all(dec);
    BIO_free_all(src);
    return 0;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
