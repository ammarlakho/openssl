/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p4_tp1_s10_260827_135842.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    BIO *b_mem_enc = NULL, *b_cipher_enc = NULL;
    BIO *b_mem_dec = NULL, *b_cipher_dec = NULL;
    unsigned char key[32], iv[16];
    unsigned char ciphertext[256];
    unsigned char decrypted[256];
    const char *plaintext = "The quick brown fox jumps over the lazy dog";
    int len = (int)strlen(plaintext);
    int ciphertext_len = 0;
    int decrypted_len = 0;
    int ret = 0;

    memset(key, 0x41, sizeof(key));
    memset(iv, 0x42, sizeof(iv));

    /* Encryption Phase */
    if (!TEST_ptr((b_mem_enc = BIO_new(BIO_s_mem()))))
        goto err;
    if (!TEST_ptr((b_cipher_enc = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_true(BIO_push(b_cipher_enc, b_mem_enc)))
        goto err;
    if (!TEST_true(BIO_set_cipher(b_cipher_enc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (!TEST_true(BIO_write(b_cipher_enc, plaintext, len) == len))
        goto err;
    if (!TEST_true(BIO_ctrl(b_cipher_enc, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    ciphertext_len = BIO_read(b_mem_enc, ciphertext, sizeof(ciphertext));
    if (ciphertext_len <= 0)
        goto err;

    BIO_free_all(b_cipher_enc);

    /* Decryption Phase */
    if (!TEST_ptr((b_mem_dec = BIO_new(BIO_s_mem()))))
        goto err;
    if (!TEST_true(BIO_write(b_mem_dec, ciphertext, ciphertext_len) == ciphertext_len))
        goto err;
    if (!TEST_ptr((b_cipher_dec = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_true(BIO_push(b_cipher_dec, b_mem_dec)))
        goto err;
    if (!TEST_true(BIO_set_cipher(b_cipher_dec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    decrypted_len = BIO_read(b_cipher_dec, decrypted, sizeof(decrypted));
    if (decrypted_len <= 0)
        goto err;

    BIO_free_all(b_cipher_dec);

    if (!TEST_mem_eq(plaintext, len, decrypted, decrypted_len))
        goto err;

    ret = 1;

err:
    if (b_cipher_enc)
        BIO_free_all(b_cipher_enc);
    if (b_mem_enc)
        BIO_free(b_mem_enc);
    if (b_cipher_dec)
        BIO_free_all(b_cipher_dec);
    if (b_mem_dec)
        BIO_free(b_mem_dec);

    return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
