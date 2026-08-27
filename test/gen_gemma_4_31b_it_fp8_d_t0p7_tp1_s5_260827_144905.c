/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p7_tp1_s5_260827_144905.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    unsigned char iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    const char *plaintext = "The quick brown fox jumps over the lazy dog";
    int pt_len = (int)strlen(plaintext);
    unsigned char ciphertext[256];
    unsigned char decrypted[256];
    int ct_len = 0, dec_len = 0;
    BIO *b_mem_enc = NULL, *b_cipher_enc = NULL;
    BIO *b_mem_dec = NULL, *b_cipher_dec = NULL;

    /* 1. Setup Encryption Chain: Cipher BIO -> Memory BIO */
    if (!TEST_ptr((b_mem_enc = BIO_new(BIO_s_mem()))))
        goto err;
    if (!TEST_ptr((b_cipher_enc = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_true(BIO_push(b_cipher_enc, b_mem_enc)))
        goto err;

    /* Configure AES-256-CBC for encryption */
    if (!TEST_true(BIO_set_cipher(b_cipher_enc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    /* Write plaintext through the cipher BIO */
    if (!TEST_true(BIO_write(b_cipher_enc, plaintext, pt_len) == pt_len))
        goto err;

    /* Flush to ensure padding is processed and written to the memory BIO */
    if (!TEST_true(BIO_ctrl(b_cipher_enc, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    /* Read the encrypted data from the memory BIO */
    ct_len = BIO_read(b_mem_enc, ciphertext, sizeof(ciphertext));
    if (ct_len <= 0)
        goto err;

    /* 2. Setup Decryption Chain: Cipher BIO -> Memory BIO (containing ciphertext) */
    if (!TEST_ptr((b_mem_dec = BIO_new_mem_buf(ciphertext, ct_len))))
        goto err;
    if (!TEST_ptr((b_cipher_dec = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_true(BIO_push(b_cipher_dec, b_mem_dec)))
        goto err;

    /* Configure AES-256-CBC for decryption */
    if (!TEST_true(BIO_set_cipher(b_cipher_dec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    /* Read decrypted data from the cipher BIO */
    dec_len = BIO_read(b_cipher_dec, decrypted, sizeof(decrypted));
    if (dec_len <= 0)
        goto err;

    /* Verify results */
    if (!TEST_mem_eq(plaintext, pt_len, decrypted, dec_len))
        goto err;
    if (!TEST_true(pt_len == dec_len))
        goto err;

    BIO_free_all(b_cipher_enc);
    BIO_free_all(b_cipher_dec);
    return 1;

err:
    if (b_cipher_enc) BIO_free_all(b_cipher_enc);
    if (b_cipher_dec) BIO_free_all(b_cipher_dec);
    return 0;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
