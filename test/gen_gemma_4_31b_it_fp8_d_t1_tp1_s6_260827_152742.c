/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t1_tp1_s6_260827_152742.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    unsigned char key[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };
    unsigned char iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    const char *plaintext = "The quick brown fox jumps over the lazy dog";
    int plaintext_len = (int)strlen(plaintext);
    unsigned char decrypted[128];
    BIO *bmem_enc = NULL, *bcipher_enc = NULL;
    BIO *bmem_dec = NULL, *bcipher_dec = NULL;
    char *cipher_data = NULL;
    long cipher_len = 0;
    int read_len = 0;
    int n;

    /* --- Encryption Path --- */
    bmem_enc = BIO_new(BIO_s_mem());
    if (!TEST_ptr(bmem_enc))
        return 0;

    bcipher_enc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bcipher_enc)) {
        BIO_free(bmem_enc);
        return 0;
    }
    BIO_push(bcipher_enc, bmem_enc);

    if (!TEST_true(BIO_set_cipher(bcipher_enc, EVP_aes_256_cbc(), key, iv, 1))) {
        BIO_free(bcipher_enc);
        return 0;
    }

    if (!TEST_true(BIO_write(bcipher_enc, plaintext, plaintext_len) == plaintext_len)) {
        BIO_free(bcipher_enc);
        return 0;
    }

    /* Finalize encryption (handle padding) */
    if (!TEST_true(BIO_ctrl(bcipher_enc, BIO_CTRL_FLUSH, 0, NULL))) {
        BIO_free(bcipher_enc);
        return 0;
    }

    cipher_len = BIO_get_mem_data(bmem_enc, &cipher_data);
    if (!TEST_true(cipher_len > 0)) {
        BIO_free(bcipher_enc);
        return 0;
    }

    /* --- Decryption Path --- */
    bmem_dec = BIO_new_mem_buf(cipher_data, cipher_len);
    if (!TEST_ptr(bmem_dec)) {
        BIO_free(bcipher_enc);
        return 0;
    }

    bcipher_dec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bcipher_dec)) {
        BIO_free(bmem_dec);
        BIO_free(bcipher_enc);
        return 0;
    }
    BIO_push(bcipher_dec, bmem_dec);

    if (!TEST_true(BIO_set_cipher(bcipher_dec, EVP_aes_256_cbc(), key, iv, 0))) {
        BIO_free(bcipher_dec);
        BIO_free(bcipher_enc);
        return 0;
    }

    /* Read until EOF to ensure EVP_CipherFinal_ex is called in enc_read */
    while ((n = BIO_read(bcipher_dec, (char *)decrypted + read_len, sizeof(decrypted) - read_len)) > 0) {
        read_len += n;
    }

    if (!TEST_true(read_len == plaintext_len)) {
        BIO_free(bcipher_dec);
        BIO_free(bcipher_enc);
        return 0;
    }

    if (!TEST_mem_eq(plaintext, plaintext_len, decrypted, read_len)) {
        BIO_free(bcipher_dec);
        BIO_free(bcipher_enc);
        return 0;
    }

    BIO_free(bcipher_dec);
    BIO_free(bcipher_enc);
    return 1;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
