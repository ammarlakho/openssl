/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p4_tp1_s5_260827_134837.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    int plaintext_len = (int)strlen(plaintext);
    unsigned char ciphertext[256];
    unsigned char decrypted[256];
    int cipher_len = 0;
    int dec_len = 0;
    BIO *benc = NULL, *bmem = NULL, *bdec = NULL;

    /* Initialize key and IV with fixed values for deterministic testing */
    memset(key, 0x41, sizeof(key));
    memset(iv, 0x42, sizeof(iv));

    /* 
     * Encryption Path: 
     * BIO_f_cipher (Encrypt) -> BIO_s_mem 
     */
    bmem = BIO_new(BIO_s_mem());
    if (!TEST_ptr(bmem))
        return 0;

    benc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(benc)) {
        BIO_free(bmem);
        return 0;
    }
    BIO_push(benc, bmem);

    if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(), key, iv, 1))) {
        BIO_free_all(benc);
        return 0;
    }

    if (!TEST_true(BIO_write(benc, plaintext, plaintext_len) == plaintext_len)) {
        BIO_free_all(benc);
        return 0;
    }

    /* Flush to ensure EVP_CipherFinal_ex is called and padding is written */
    if (!TEST_true(BIO_ctrl(benc, BIO_CTRL_FLUSH, 0, NULL) == 1)) {
        BIO_free_all(benc);
        return 0;
    }

    char *cptr = NULL;
    long clen = 0;
    BIO_get_mem_data(bmem, &cptr, &clen);
    cipher_len = (int)clen;
    if (cipher_len <= 0 || cipher_len > (int)sizeof(ciphertext)) {
        BIO_free_all(benc);
        return 0;
    }
    memcpy(ciphertext, cptr, cipher_len);
    BIO_free_all(benc);

    /* 
     * Decryption Path: 
     * BIO_f_cipher (Decrypt) -> BIO_s_mem (from buffer) 
     */
    BIO *bmem_in = BIO_new_mem_buf(ciphertext, cipher_len);
    if (!TEST_ptr(bmem_in))
        return 0;

    bdec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bdec)) {
        BIO_free(bmem_in);
        return 0;
    }
    BIO_push(bdec, bmem_in);

    if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(), key, iv, 0))) {
        BIO_free_all(bdec);
        return 0;
    }

    /* Read decrypted data */
    dec_len = BIO_read(bdec, (char *)decrypted, sizeof(decrypted));
    if (!TEST_true(dec_len == plaintext_len)) {
        BIO_free_all(bdec);
        return 0;
    }

    /* Verify round-trip result matches original plaintext */
    if (!TEST_mem_eq(plaintext, plaintext_len, decrypted, dec_len)) {
        BIO_free_all(bdec);
        return 0;
    }

    BIO_free_all(bdec);
    return 1;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
