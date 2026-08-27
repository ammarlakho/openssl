/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p4_tp1_s7_260827_135238.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    const char *plaintext = "The quick brown fox jumps over the lazy dog";
    int plaintext_len = (int)strlen(plaintext);
    unsigned char ciphertext[128];
    unsigned char decrypted[128];
    int ct_len = 0;
    int total_decrypted = 0;
    int read_bytes = 0;

    /* Initialize key and IV with fixed values for reproducibility */
    memset(key, 0x41, 32);
    memset(iv, 0x42, 16);
    memset(decrypted, 0, sizeof(decrypted));

    /* Setup Encryption Chain: Cipher Filter -> Memory BIO */
    if (!TEST_ptr(b_mem_enc = BIO_new(BIO_s_mem())))
        return 0;
    if (!TEST_ptr(b_cipher_enc = BIO_new(BIO_f_cipher()))) {
        BIO_free(b_mem_enc);
        return 0;
    }
    if (!TEST_true(BIO_push(b_cipher_enc, b_mem_enc))) {
        BIO_free_all(b_cipher_enc);
        return 0;
    }

    /* Set AES-256-CBC for encryption */
    if (!TEST_true(BIO_set_cipher(b_cipher_enc, EVP_aes_256_cbc(), key, iv, 1))) {
        BIO_free_all(b_cipher_enc);
        return 0;
    }

    /* Write plaintext and flush to ensure padding is processed */
    if (!TEST_true(BIO_write(b_cipher_enc, plaintext, plaintext_len) == plaintext_len)) {
        BIO_free_all(b_cipher_enc);
        return 0;
    }
    if (!TEST_true(BIO_ctrl(b_cipher_enc, BIO_CTRL_FLUSH, 0, NULL))) {
        BIO_free_all(b_cipher_enc);
        return 0;
    }

    /* Extract ciphertext from the memory BIO */
    char *ct_ptr = NULL;
    ct_len = BIO_get_mem_data(b_mem_enc, &ct_ptr);
    if (ct_len <= 0 || ct_ptr == NULL) {
        BIO_free_all(b_cipher_enc);
        return 0;
    }
    memcpy(ciphertext, ct_ptr, ct_len);
    BIO_free_all(b_cipher_enc);

    /* Setup Decryption Chain: Cipher Filter -> Memory BIO (containing ciphertext) */
    if (!TEST_ptr(b_mem_dec = BIO_new(BIO_s_mem())))
        return 0;
    if (!TEST_true(BIO_write(b_mem_dec, ciphertext, ct_len) == ct_len)) {
        BIO_free(b_mem_dec);
        return 0;
    }
    if (!TEST_ptr(b_cipher_dec = BIO_new(BIO_f_cipher()))) {
        BIO_free(b_mem_dec);
        return 0;
    }
    if (!TEST_true(BIO_push(b_cipher_dec, b_mem_dec))) {
        BIO_free_all(b_cipher_dec);
        return 0;
    }

    /* Set AES-256-CBC for decryption */
    if (!TEST_true(BIO_set_cipher(b_cipher_dec, EVP_aes_256_cbc(), key, iv, 0))) {
        BIO_free_all(b_cipher_dec);
        return 0;
    }

    /* Read decrypted data until EOF */
    while ((read_bytes = BIO_read(b_cipher_dec, decrypted + total_decrypted, 
                                  sizeof(decrypted) - total_decrypted)) > 0) {
        total_decrypted += read_bytes;
    }

    /* Verify the decrypted plaintext matches the original */
    int result = TEST_mem_eq(plaintext, plaintext_len, decrypted, total_decrypted);
    
    BIO_free_all(b_cipher_dec);
    return result;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
