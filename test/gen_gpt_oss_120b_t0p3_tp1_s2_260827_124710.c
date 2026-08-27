/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p3_tp1_s2_260827_124710.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    int ok = 0;
    const unsigned char key[32] = {0};
    const unsigned char iv[16] = {0};
    const unsigned char plaintext[] = "OpenSSL BIO cipher test vector";
    size_t pt_len = sizeof(plaintext) - 1; /* omit terminating NUL */
    unsigned char *exp_ct = NULL;
    int exp_len = 0, outlen = 0, tmplen = 0;
    EVP_CIPHER_CTX *cctx = NULL;
    BIO *mem = NULL, *cipher = NULL;
    char *enc_data = NULL;
    long enc_len = 0;
    unsigned char *ciphertext = NULL;
    BIO *mem2 = NULL, *dec = NULL;
    unsigned char outbuf[128];
    int outlen2 = 0;

    /* ------------------------------------------------------------
     * Produce the expected ciphertext using the EVP API.
     * ------------------------------------------------------------ */
    cctx = EVP_CIPHER_CTX_new();
    if (!TEST_ptr(cctx))
        goto end;
    if (!TEST_true(EVP_EncryptInit_ex(cctx, EVP_aes_256_cbc(),
                                      NULL, key, iv)))
        goto end;

    exp_ct = OPENSSL_malloc(pt_len + EVP_MAX_BLOCK_LENGTH);
    if (!TEST_ptr(exp_ct))
        goto end;

    if (!TEST_true(EVP_EncryptUpdate(cctx, exp_ct, &outlen,
                                     plaintext, (int)pt_len)))
        goto end;
    if (!TEST_true(EVP_EncryptFinal_ex(cctx,
                                       exp_ct + outlen, &tmplen)))
        goto end;
    exp_len = outlen + tmplen;

    /* ------------------------------------------------------------
     * Encrypt via BIO_f_cipher and compare with the EVP result.
     * ------------------------------------------------------------ */
    mem = BIO_new(BIO_s_mem());
    if (!TEST_ptr(mem))
        goto end;
    cipher = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(cipher))
        goto end;
    if (!TEST_true(BIO_set_cipher(cipher,
                                  EVP_aes_256_cbc(),
                                  key, iv, 1)))   /* encrypt */
        goto end;

    BIO_push(cipher, mem);
    if (!TEST_int_eq(BIO_write(cipher,
                               (const char *)plaintext,
                               (int)pt_len), (int)pt_len))
        goto end;
    if (!TEST_true(BIO_flush(cipher)))
        goto end;

    enc_len = BIO_get_mem_data(mem, &enc_data);
    if (!TEST_int_eq((int)enc_len, exp_len))
        goto end;
    if (!TEST_mem_eq(enc_data, (size_t)enc_len, exp_ct, (size_t)exp_len))
        goto end;

    /* Keep a copy of the ciphertext for the decryption step. */
    ciphertext = OPENSSL_malloc((size_t)enc_len);
    if (!TEST_ptr(ciphertext))
        goto end;
    memcpy(ciphertext, enc_data, (size_t)enc_len);

    /* ------------------------------------------------------------
     * Decrypt the ciphertext via BIO_f_cipher and verify the plaintext.
     * ------------------------------------------------------------ */
    mem2 = BIO_new_mem_buf(ciphertext, (int)enc_len);
    if (!TEST_ptr(mem2))
        goto end;
    dec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(dec))
        goto end;
    if (!TEST_true(BIO_set_cipher(dec,
                                  EVP_aes_256_cbc(),
                                  key, iv, 0)))   /* decrypt */
        goto end;

    BIO_push(dec, mem2);
    outlen2 = BIO_read(dec, outbuf, sizeof(outbuf));
    if (!TEST_int_eq(outlen2, (int)pt_len))
        goto end;
    if (!TEST_mem_eq(outbuf, (size_t)outlen2,
                    plaintext, pt_len))
        goto end;

    ok = 1;   /* all checks passed */

end:
    EVP_CIPHER_CTX_free(cctx);
    OPENSSL_free(exp_ct);
    OPENSSL_free(ciphertext);
    BIO_free_all(cipher);
    BIO_free(mem);
    BIO_free_all(dec);
    BIO_free(mem2);
    return ok;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
