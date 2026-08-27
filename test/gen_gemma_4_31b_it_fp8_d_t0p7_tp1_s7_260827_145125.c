/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p7_tp1_s7_260827_145125.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    unsigned char key[32];
    unsigned char iv[16];
    const char *plaintext = "The quick brown fox jumps over the lazy dog";
    int pt_len = (int)strlen(plaintext);
    unsigned char decrypted[128];
    int read_len;
    BIO *b_mem = NULL, *b_enc = NULL, *b_dec = NULL;

    /* Initialize key and IV with fixed values */
    memset(key, 0x41, sizeof(key));
    memset(iv, 0x42, sizeof(iv));

    /* 1. Setup Encryption Chain: BIO_f_cipher -> BIO_s_mem */
    if (!TEST_ptr((b_mem = BIO_new(BIO_s_mem()))))
        return 0;
    if (!TEST_ptr((b_enc = BIO_new(BIO_f_cipher())))) {
        BIO_free(b_mem);
        return 0;
    }
    if (!TEST_true(BIO_push(b_enc, b_mem))) {
        BIO_free_all(b_enc);
        return 0;
    }

    /* Configure for AES-256-CBC Encryption */
    if (!TEST_true(BIO_set_cipher(b_enc, EVP_aes_256_cbc(), key, iv, 1))) {
        BIO_free_all(b_enc);
        return 0;
    }

    /* Write plaintext and flush to trigger padding/final block */
    if (!TEST_true(BIO_write(b_enc, plaintext, pt_len) == pt_len)) {
        BIO_free_all(b_enc);
        return 0;
    }
    if (!TEST_true(BIO_ctrl(b_enc, BIO_CTRL_FLUSH, 0, NULL))) {
        BIO_free_all(b_enc);
        return 0;
    }

    /* Remove the encryption filter but keep the memory BIO containing ciphertext */
    BIO_free(b_enc);

    /* 2. Setup Decryption Chain: BIO_f_cipher -> BIO_s_mem (containing ciphertext) */
    /* Reset memory BIO offset to the beginning of the ciphertext */
    BIO_set_mem_offset(b_mem, 0);

    if (!TEST_ptr((b_dec = BIO_new(BIO_f_cipher())))) {
        BIO_free(b_mem);
        return 0;
    }
    if (!TEST_true(BIO_push(b_dec, b_mem))) {
        BIO_free_all(b_dec);
        return 0;
    }

    /* Configure for AES-256-CBC Decryption */
    if (!TEST_true(BIO_set_cipher(b_dec, EVP_aes_256_cbc(), key, iv, 0))) {
        BIO_free_all(b_dec);
        return 0;
    }

    /* Read decrypted data from the chain */
    read_len = BIO_read(b_dec, decrypted, sizeof(decrypted));
    if (read_len <= 0) {
        BIO_free_all(b_dec);
        return 0;
    }

    /* Verify the round-trip result matches the original plaintext */
    int result = TEST_mem_eq(plaintext, pt_len, decrypted, read_len);

    BIO_free_all(b_dec);
    return result;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
