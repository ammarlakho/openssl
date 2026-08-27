/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p5_tp1_s8_260827_141355.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    const char *plaintext = "The quick brown fox jumps over the lazy dog";
    int plain_len = (int)strlen(plaintext);
    unsigned char key[32];
    unsigned char iv[16];
    unsigned char ciphertext[128];
    unsigned char decrypted[128];
    int cipher_len = 0;
    int dec_len = 0;
    BIO *b_enc = NULL, *b_mem_out = NULL;
    BIO *b_dec = NULL, *b_mem_in = NULL;

    /* Initialize key and IV with fixed values */
    memset(key, 0x41, sizeof(key));
    memset(iv, 0x42, sizeof(iv));
    memset(ciphertext, 0, sizeof(ciphertext));
    memset(decrypted, 0, sizeof(decrypted));

    /* --- Encryption Phase --- */
    b_mem_out = BIO_new(BIO_s_mem());
    if (!TEST_ptr(b_mem_out))
        goto err;

    b_enc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(b_enc))
        goto err;

    if (!TEST_true(BIO_push(b_enc, b_mem_out)))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_enc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (!TEST_true(BIO_write(b_enc, plaintext, plain_len) > 0))
        goto err;

    /* Flush is mandatory to process the final block and padding */
    if (!TEST_true(BIO_ctrl(b_enc, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    /* Extract ciphertext from the memory BIO */
    unsigned char *ptr;
    long len;
    BIO_get_mem_data(b_mem_out, &ptr, &len);
    if (len <= 0 || len > sizeof(ciphertext))
        goto err;
    
    memcpy(ciphertext, ptr, len);
    cipher_len = (int)len;

    /* Cleanup encryption chain */
    BIO_free_all(b_enc);
    b_enc = NULL;

    /* --- Decryption Phase --- */
    b_mem_in = BIO_new_mem_buf(ciphertext, cipher_len);
    if (!TEST_ptr(b_mem_in))
        goto err;

    b_dec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(b_dec))
        goto err;

    if (!TEST_true(BIO_push(b_dec, b_mem_in)))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_dec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    dec_len = BIO_read(b_dec, (char *)decrypted, sizeof(decrypted));
    if (dec_len <= 0)
        goto err;

    /* Verify decrypted result matches original plaintext */
    if (!TEST_mem_eq(plaintext, plain_len, decrypted, dec_len))
        goto err;

    if (!TEST_true(dec_len == plain_len))
        goto err;

    BIO_free_all(b_dec);
    return 1;

err:
    if (b_enc) BIO_free_all(b_enc);
    if (b_dec) BIO_free_all(b_dec);
    return 0;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
