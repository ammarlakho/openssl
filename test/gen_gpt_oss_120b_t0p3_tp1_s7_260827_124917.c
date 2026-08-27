/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p3_tp1_s7_260827_124917.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    /* Test vector data */
    const unsigned char key[32] = { 0 };
    const unsigned char iv[16]  = { 0 };
    const unsigned char plaintext[] =
        "OpenSSL BIO cipher test vector data.";
    const int ptlen = (int)sizeof(plaintext) - 1;

    /* Buffers for expected ciphertext and decrypted output */
    unsigned char expected[128];
    unsigned char *ciphertext = NULL;
    unsigned char decrypted[128];

    EVP_CIPHER_CTX *c = NULL;
    BIO *mem = NULL, *cipher = NULL;
    char *enc_ptr = NULL;
    long enc_len = 0;
    int outlen = 0, tmplen = 0;
    int dec_len = 0;
    int ok = 1;

    /* ------------------------------------------------------------
     * 1. Compute the expected ciphertext using the EVP API.
     * ------------------------------------------------------------ */
    c = EVP_CIPHER_CTX_new();
    if (!TEST_ptr(c))
        return 0;

    if (!TEST_true(EVP_EncryptInit_ex(c, EVP_aes_256_cbc(),
                                      NULL, key, iv)))
        ok = 0;
    if (!TEST_true(EVP_EncryptUpdate(c, expected, &outlen,
                                     plaintext, ptlen)))
        ok = 0;
    if (!TEST_true(EVP_EncryptFinal_ex(c, expected + outlen, &tmplen)))
        ok = 0;
    outlen += tmplen;               /* total ciphertext length */
    EVP_CIPHER_CTX_free(c);
    c = NULL;
    if (!ok)
        goto cleanup;

    /* ------------------------------------------------------------
     * 2. Encrypt the same plaintext through a BIO chain.
     * ------------------------------------------------------------ */
    mem = BIO_new(BIO_s_mem());
    if (!TEST_ptr(mem)) { ok = 0; goto cleanup; }

    cipher = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(cipher)) { ok = 0; goto cleanup; }

    if (!TEST_true(BIO_set_cipher(cipher, EVP_aes_256_cbc(),
                                  key, iv, 1)))   /* encrypt */
        ok = 0;

    BIO_push(cipher, mem);

    if (BIO_write(cipher, plaintext, ptlen) != ptlen)
        ok = 0;
    if (!TEST_true(BIO_flush(cipher)))   /* forces final block */
        ok = 0;

    enc_len = BIO_get_mem_data(mem, &enc_ptr);
    if (!TEST_int_eq((int)enc_len, outlen))
        ok = 0;
    if (!TEST_mem_eq(enc_ptr, (size_t)enc_len,
                     expected, (size_t)outlen))
        ok = 0;

    /* Keep a copy of the ciphertext before freeing the BIO */
    ciphertext = OPENSSL_malloc((size_t)enc_len);
    if (!TEST_ptr(ciphertext)) { ok = 0; goto cleanup; }
    memcpy(ciphertext, enc_ptr, (size_t)enc_len);

    /* ------------------------------------------------------------
     * 3. Decrypt the ciphertext through a BIO chain and compare.
     * ------------------------------------------------------------ */
    BIO_free_all(cipher);
    cipher = NULL;
    BIO_free(mem);
    mem = NULL;

    mem = BIO_new_mem_buf(ciphertext, (int)enc_len);
    if (!TEST_ptr(mem)) { ok = 0; goto cleanup; }

    cipher = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(cipher)) { ok = 0; goto cleanup; }

    if (!TEST_true(BIO_set_cipher(cipher, EVP_aes_256_cbc(),
                                  key, iv, 0)))   /* decrypt */
        ok = 0;

    BIO_push(cipher, mem);

    dec_len = BIO_read(cipher, decrypted, sizeof(decrypted));
    if (!TEST_int_gt(dec_len, 0))
        ok = 0;
    if (!TEST_mem_eq(decrypted, (size_t)dec_len,
                     plaintext, (size_t)ptlen))
        ok = 0;

cleanup:
    BIO_free_all(cipher);
    BIO_free(mem);
    EVP_CIPHER_CTX_free(c);
    OPENSSL_free(ciphertext);
    return ok;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
