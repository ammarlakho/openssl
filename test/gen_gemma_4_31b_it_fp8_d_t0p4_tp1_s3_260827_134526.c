/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p4_tp1_s3_260827_134526.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    int plaintext_len = (int)strlen(plaintext);
    unsigned char decrypted[128];
    int decrypted_len = 0;
    BIO *benc = NULL, *bmem_out = NULL, *bdec = NULL, *bmem_in = NULL;
    char *cipher_ptr = NULL;
    long cipher_len = 0;

    /* Encryption Chain: BIO_f_cipher -> BIO_s_mem */
    bmem_out = BIO_new(BIO_s_mem());
    if (!TEST_ptr(bmem_out))
        return 0;

    benc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(benc)) {
        BIO_free(bmem_out);
        return 0;
    }

    if (!TEST_true(BIO_push(benc, bmem_out))) {
        BIO_free_all(benc);
        return 0;
    }

    if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(), key, iv, 1))) {
        BIO_free_all(benc);
        return 0;
    }

    if (!TEST_true(BIO_write(benc, plaintext, plaintext_len) > 0)) {
        BIO_free_all(benc);
        return 0;
    }

    /* Flush is critical to process the final block and padding */
    if (!TEST_true(BIO_ctrl(benc, BIO_CTRL_FLUSH, 0, NULL))) {
        BIO_free_all(benc);
        return 0;
    }

    cipher_len = BIO_get_mem_data(bmem_out, &cipher_ptr);
    if (cipher_len <= 0) {
        BIO_free_all(benc);
        return 0;
    }

    /* Decryption Chain: BIO_f_cipher -> BIO_s_mem (containing ciphertext) */
    bmem_in = BIO_new_mem_buf(cipher_ptr, cipher_len);
    if (!TEST_ptr(bmem_in)) {
        BIO_free_all(benc);
        return 0;
    }

    bdec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bdec)) {
        BIO_free(bmem_in);
        BIO_free_all(benc);
        return 0;
    }

    if (!TEST_true(BIO_push(bdec, bmem_in))) {
        BIO_free_all(bdec);
        BIO_free_all(benc);
        return 0;
    }

    if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(), key, iv, 0))) {
        BIO_free_all(bdec);
        BIO_free_all(benc);
        return 0;
    }

    while (decrypted_len < (int)sizeof(decrypted)) {
        int n = BIO_read(bdec, (char *)(decrypted + decrypted_len), 
                         (int)sizeof(decrypted) - decrypted_len);
        if (n <= 0)
            break;
        decrypted_len += n;
    }

    int result = TEST_mem_eq(plaintext, plaintext_len, decrypted, decrypted_len);

    BIO_free_all(bdec);
    BIO_free_all(benc);

    return result;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
