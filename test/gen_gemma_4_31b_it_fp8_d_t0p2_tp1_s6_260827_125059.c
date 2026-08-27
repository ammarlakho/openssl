/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p2_tp1_s6_260827_125059.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    const EVP_CIPHER *cipher;
    BIO *bmem = NULL, *benc = NULL;
    BIO *bmem_dec = NULL, *bdec = NULL;
    unsigned char key[32], iv[16];
    unsigned char ciphertext[1024];
    unsigned char decrypted[1024];
    const char *plaintext = "The quick brown fox jumps over the lazy dog";
    int plaintext_len = (int)strlen(plaintext);
    int ct_len, total_read = 0, read_len;

    memset(key, 0x42, sizeof(key));
    memset(iv, 0x24, sizeof(iv));

    if (!TEST_ptr(cipher = EVP_aes_256_cbc()))
        return 0;

    /* --- Encryption Phase --- */
    if (!TEST_ptr(bmem = BIO_new(BIO_s_mem())))
        return 0;
    if (!TEST_ptr(benc = BIO_push(bmem, BIO_f_cipher()))) {
        BIO_free(bmem);
        return 0;
    }

    if (!TEST_true(BIO_set_cipher(benc, cipher, key, iv, 1))) {
        BIO_free_all(benc);
        return 0;
    }

    if (!TEST_true(BIO_write(benc, plaintext, plaintext_len) == plaintext_len)) {
        BIO_free_all(benc);
        return 0;
    }

    /* Flush is required to process the final block and padding */
    if (!TEST_true(BIO_ctrl(benc, BIO_CTRL_FLUSH, 0, NULL) == 1)) {
        BIO_free_all(benc);
        return 0;
    }

    /* Extract ciphertext from the underlying memory BIO */
    if (!TEST_true(BIO_set_mem_offset(bmem, 0) == 1)) {
        BIO_free_all(benc);
        return 0;
    }
    ct_len = BIO_read(bmem, ciphertext, sizeof(ciphertext));
    if (!TEST_true(ct_len > 0)) {
        BIO_free_all(benc);
        return 0;
    }

    /* --- Decryption Phase --- */
    if (!TEST_ptr(bmem_dec = BIO_new(BIO_s_mem()))) {
        BIO_free_all(benc);
        return 0;
    }

    if (!TEST_true(BIO_write(bmem_dec, ciphertext, ct_len) == ct_len)) {
        BIO_free_all(benc);
        BIO_free(bmem_dec);
        return 0;
    }

    if (!TEST_true(BIO_set_mem_offset(bmem_dec, 0) == 1)) {
        BIO_free_all(benc);
        BIO_free(bmem_dec);
        return 0;
    }

    if (!TEST_ptr(bdec = BIO_push(bmem_dec, BIO_f_cipher()))) {
        BIO_free_all(benc);
        BIO_free(bmem_dec);
        return 0;
    }

    if (!TEST_true(BIO_set_cipher(bdec, cipher, key, iv, 0))) {
        BIO_free_all(benc);
        BIO_free_all(bdec);
        return 0;
    }

    /* Read from the cipher BIO to decrypt */
    while ((read_len = BIO_read(bdec, decrypted + total_read, sizeof(decrypted) - total_read)) > 0) {
        total_read += read_len;
    }

    if (!TEST_true(total_read == plaintext_len)) {
        BIO_free_all(benc);
        BIO_free_all(bdec);
        return 0;
    }

    if (!TEST_mem_eq(plaintext, plaintext_len, decrypted, total_read)) {
        BIO_free_all(benc);
        BIO_free_all(bdec);
        return 0;
    }

    BIO_free_all(benc);
    BIO_free_all(bdec);

    return 1;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
