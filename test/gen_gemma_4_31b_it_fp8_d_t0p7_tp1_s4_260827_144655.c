/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p7_tp1_s4_260827_144655.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    unsigned char key[32], iv[16];
    memset(key, 0x42, 32);
    memset(iv, 0x24, 16);
    const char *plain = "The quick brown fox jumps over the lazy dog";
    int plain_len = (int)strlen(plain);
    unsigned char decrypted[128];
    int dec_len;
    BIO *enc_bio = NULL, *dec_bio = NULL;
    char *ct_ptr = NULL;
    long ct_len;

    /* 
     * 1. Encryption Phase
     * Chain: BIO_f_cipher -> BIO_s_mem
     */
    BIO *mem_out = BIO_new(BIO_s_mem());
    if (!TEST_ptr(mem_out))
        return 0;

    enc_bio = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(enc_bio)) {
        BIO_free(mem_out);
        return 0;
    }
    BIO_push(enc_bio, mem_out);

    if (!TEST_true(BIO_set_cipher(enc_bio, EVP_aes_256_cbc(), key, iv, 1))) {
        BIO_free_all(enc_bio);
        return 0;
    }

    if (!TEST_true(BIO_write(enc_bio, plain, plain_len) == plain_len)) {
        BIO_free_all(enc_bio);
        return 0;
    }

    /* Flush is required to process EVP_CipherFinal_ex (padding) */
    if (!TEST_true(BIO_ctrl(enc_bio, BIO_CTRL_FLUSH, 0, NULL) == 1)) {
        BIO_free_all(enc_bio);
        return 0;
    }

    /* Extract ciphertext from the memory BIO */
    ct_len = BIO_get_mem_data(mem_out, &ct_ptr);
    if (!TEST_true(ct_len > 0)) {
        BIO_free_all(enc_bio);
        return 0;
    }

    /* 
     * 2. Decryption Phase
     * Chain: BIO_f_cipher -> BIO_s_mem (initialized with ciphertext)
     */
    BIO *mem_in = BIO_new_mem_buf(ct_ptr, ct_len);
    if (!TEST_ptr(mem_in)) {
        BIO_free_all(enc_bio);
        return 0;
    }

    dec_bio = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(dec_bio)) {
        BIO_free_all(enc_bio);
        BIO_free(mem_in);
        return 0;
    }
    BIO_push(dec_bio, mem_in);

    if (!TEST_true(BIO_set_cipher(dec_bio, EVP_aes_256_cbc(), key, iv, 0))) {
        BIO_free_all(enc_bio);
        BIO_free_all(dec_bio);
        return 0;
    }

    dec_len = BIO_read(dec_bio, decrypted, sizeof(decrypted));
    if (!TEST_true(dec_len == plain_len)) {
        BIO_free_all(enc_bio);
        BIO_free_all(dec_bio);
        return 0;
    }

    if (!TEST_mem_eq(plain, plain_len, decrypted, dec_len)) {
        BIO_free_all(enc_bio);
        BIO_free_all(dec_bio);
        return 0;
    }

    BIO_free_all(enc_bio);
    BIO_free_all(dec_bio);
    return 1;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
