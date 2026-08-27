/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p3_tp1_s8_260827_133308.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    unsigned char key[32] = "01234567890123456789012345678901";
    unsigned char iv[16] = "0123456789012345";
    const unsigned char plaintext[] = "The quick brown fox jumps over the lazy dog";
    int pt_len = (int)sizeof(plaintext) - 1;
    unsigned char ciphertext[128];
    unsigned char decrypted[128];
    int ct_len, dec_len;
    BIO *b_enc = NULL, *b_mem = NULL, *b_dec = NULL, *b_mem_dec = NULL;

    /* Encryption: Plaintext -> BIO_f_cipher -> BIO_s_mem */
    b_mem = BIO_new(BIO_s_mem());
    if (!TEST_ptr(b_mem))
        return 0;

    b_enc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(b_enc)) {
        BIO_free(b_mem);
        return 0;
    }

    if (!TEST_true(BIO_push(b_enc, b_mem))) {
        BIO_free_all(b_enc);
        return 0;
    }

    if (!TEST_true(BIO_set_cipher(b_enc, EVP_aes_256_cbc(), key, iv, 1))) {
        BIO_free_all(b_enc);
        return 0;
    }

    if (!TEST_true(BIO_write(b_enc, plaintext, pt_len) == pt_len)) {
        BIO_free_all(b_enc);
        return 0;
    }

    /* Flush to ensure padding is written to the memory BIO */
    if (!TEST_true(BIO_ctrl(b_enc, BIO_CTRL_FLUSH, 0, NULL))) {
        BIO_free_all(b_enc);
        return 0;
    }

    /* Read encrypted data from the sink BIO */
    ct_len = BIO_read(b_mem, ciphertext, (int)sizeof(ciphertext));
    if (!TEST_true(ct_len > 0)) {
        BIO_free_all(b_enc);
        return 0;
    }

    /* Decryption: BIO_s_mem (ciphertext) -> BIO_f_cipher -> Output */
    b_mem_dec = BIO_new_mem_buf(ciphertext, ct_len);
    if (!TEST_ptr(b_mem_dec)) {
        BIO_free_all(b_enc);
        return 0;
    }

    b_dec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(b_dec)) {
        BIO_free(b_mem_dec);
        BIO_free_all(b_enc);
        return 0;
    }

    if (!TEST_true(BIO_push(b_dec, b_mem_dec))) {
        BIO_free_all(b_dec);
        BIO_free_all(b_enc);
        return 0;
    }

    if (!TEST_true(BIO_set_cipher(b_dec, EVP_aes_256_cbc(), key, iv, 0))) {
        BIO_free_all(b_dec);
        BIO_free_all(b_enc);
        return 0;
    }

    dec_len = BIO_read(b_dec, decrypted, (int)sizeof(decrypted));
    if (!TEST_true(dec_len == pt_len)) {
        BIO_free_all(b_dec);
        BIO_free_all(b_enc);
        return 0;
    }

    if (!TEST_mem_eq(plaintext, pt_len, decrypted, dec_len)) {
        BIO_free_all(b_dec);
        BIO_free_all(b_enc);
        return 0;
    }

    BIO_free_all(b_dec);
    BIO_free_all(b_enc);

    return 1;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
