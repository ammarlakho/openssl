/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: generated_test.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#include "testutil.h"

static int test_bio_enc_generated_smoke(void)
{
    /* BEGIN_LLM_REPLACE */
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    unsigned char key[32] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    unsigned char iv[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const unsigned char plaintext[] = "The quick brown fox jumps over the lazy dog's back!";
    int plaintext_len = (int)strlen((const char *)plaintext);
    unsigned char ciphertext[128];
    unsigned char decrypted[128];
    int ciphertext_len = 0;
    int decrypted_len = 0;
    BIO *mem_bio = NULL, *cipher_bio = NULL;
    EVP_CIPHER_CTX *ctx = NULL;

    mem_bio = BIO_new(BIO_s_mem());
    TEST_ptr(mem_bio);
    cipher_bio = BIO_new(BIO_f_cipher());
    TEST_ptr(cipher_bio);
    TEST_true(BIO_push(cipher_bio, mem_bio));

    /* Extract the internal cipher context to initialize it */
    if (BIO_ctrl(cipher_bio, BIO_C_GET_CIPHER_CTX, 0, &ctx) <= 0) {
        BIO_free_all(cipher_bio);
        return 0;
    }
    TEST_ptr(ctx);

    /* 1. Encryption Round-trip */
    TEST_true(EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, 1));

    int written = BIO_write(cipher_bio, plaintext, plaintext_len);
    TEST_true(written == plaintext_len);

    /* Flush is required to process final block/padding */
    TEST_true(BIO_ctrl(cipher_bio, BIO_CTRL_FLUSH, 0, NULL));

    /* Get the ciphertext from the memory BIO */
    ciphertext_len = BIO_read(mem_bio, ciphertext, sizeof(ciphertext));
    TEST_true(ciphertext_len > 0);
    TEST_true(ciphertext_len > plaintext_len); /* Should include padding */

    /* 2. Decryption Round-trip */
    /* Reset memory BIO to start */
    BIO_set_mem_offset(mem_bio, 0);

    /* Reset the cipher BIO for decryption */
    TEST_true(BIO_ctrl(cipher_bio, BIO_CTRL_RESET, 0, NULL));
    TEST_true(EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, 0));

    decrypted_len = BIO_read(cipher_bio, decrypted, sizeof(decrypted));
    TEST_true(decrypted_len == plaintext_len);

    TEST_mem_eq(plaintext, plaintext_len, decrypted, decrypted_len);

    BIO_free_all(cipher_bio);
    return 1;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated_smoke);
    return 1;
}
 
