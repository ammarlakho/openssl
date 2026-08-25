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
        const unsigned char plaintext[] =
            "The quick brown fox jumps over the lazy dog's back!";
        int plaintext_len = (int)strlen((const char *)plaintext);
        unsigned char ciphertext[128] = {0};
        unsigned char decrypted[128] = {0};
        int ciphertext_len = 0;
        int decrypted_len = 0;
        BIO *mem_bio = NULL, *cipher_bio = NULL;
        BIO *ciph_mem = NULL, *dec_bio = NULL;
        EVP_CIPHER_CTX *enc_ctx = NULL, *dec_ctx = NULL;
        char *mem_ptr = NULL;
        long mem_len = 0;

        /* ---------- encryption side ---------- */
        mem_bio = BIO_new(BIO_s_mem());
        TEST_ptr(mem_bio);
        cipher_bio = BIO_new(BIO_f_cipher());
        TEST_ptr(cipher_bio);
        TEST_true(BIO_push(cipher_bio, mem_bio));

        /* obtain internal EVP_CIPHER_CTX and initialise it for encryption */
        if (BIO_ctrl(cipher_bio, BIO_C_GET_CIPHER_CTX, 0, &enc_ctx) <= 0) {
            BIO_free_all(cipher_bio);
            return 0;
        }
        TEST_ptr(enc_ctx);
        TEST_true(EVP_CipherInit_ex(enc_ctx, cipher, NULL, key, iv, 1));

        /* write plaintext into the cipher BIO */
        TEST_int_eq(BIO_write(cipher_bio, plaintext, plaintext_len), plaintext_len);

        /* flush to make sure final block is emitted */
        TEST_true(BIO_flush(cipher_bio));

        /* retrieve the ciphertext from the underlying memory BIO */
        mem_len = BIO_get_mem_data(mem_bio, &mem_ptr);
        TEST_true(mem_len > 0);
        TEST_true(mem_len <= (long)sizeof(ciphertext));
        memcpy(ciphertext, mem_ptr, (size_t)mem_len);
        ciphertext_len = (int)mem_len;

        BIO_free_all(cipher_bio); /* also frees mem_bio */

        /* ---------- decryption side ---------- */
        ciph_mem = BIO_new_mem_buf(ciphertext, ciphertext_len);
        TEST_ptr(ciph_mem);
        dec_bio = BIO_new(BIO_f_cipher());
        TEST_ptr(dec_bio);
        TEST_true(BIO_push(dec_bio, ciph_mem));

        if (BIO_ctrl(dec_bio, BIO_C_GET_CIPHER_CTX, 0, &dec_ctx) <= 0) {
            BIO_free_all(dec_bio);
            return 0;
        }
        TEST_ptr(dec_ctx);
        TEST_true(EVP_CipherInit_ex(dec_ctx, cipher, NULL, key, iv, 0));

        decrypted_len = BIO_read(dec_bio, decrypted, sizeof(decrypted));
        TEST_int_ge(decrypted_len, 0);
        TEST_int_eq(decrypted_len, plaintext_len);
        TEST_mem_eq(decrypted, decrypted_len, plaintext, plaintext_len);

        BIO_free_all(dec_bio);
        return 1;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated_smoke);
    return 1;
}
