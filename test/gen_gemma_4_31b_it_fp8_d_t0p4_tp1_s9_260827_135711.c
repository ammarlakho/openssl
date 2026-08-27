/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p4_tp1_s9_260827_135711.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    BIO *bmem = NULL, *benc = NULL, *bdec = NULL;
    unsigned char key[32] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                               0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                               0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                               0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20 };
    unsigned char iv[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const char *plaintext = "The quick brown fox jumps over the lazy dog";
    int len = (int)strlen(plaintext);
    unsigned char result[256];
    int rlen = 0;

    /* 1. Setup Encryption Chain: BIO_f_cipher -> BIO_s_mem */
    TEST_ptr(bmem = BIO_new(BIO_s_mem()));
    TEST_ptr(benc = BIO_new(BIO_f_cipher()));
    TEST_true(BIO_push(benc, bmem));

    /* Initialize AES-256-CBC for encryption */
    TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(), key, iv, 1));

    /* Write plaintext to the cipher BIO */
    TEST_true(BIO_write(benc, plaintext, len) == len);

    /* Flush to ensure padding and final block are written to bmem */
    TEST_true(BIO_ctrl(benc, BIO_CTRL_FLUSH, 0, NULL) == 1);

    /* Free the cipher wrapper, keeping the memory BIO */
    BIO_free(benc);
    benc = NULL;

    /* 2. Setup Decryption Chain: BIO_f_cipher -> BIO_s_mem */
    /* Reset memory BIO read pointer to the beginning */
    BIO_set_mem_offset(bmem, 0);

    TEST_ptr(bdec = BIO_new(BIO_f_cipher()));
    TEST_true(BIO_push(bdec, bmem));

    /* Initialize AES-256-CBC for decryption */
    TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(), key, iv, 0));

    /* Read decrypted data back */
    rlen = BIO_read(bdec, (char *)result, len);
    TEST_true(rlen == len);
    TEST_mem_eq(plaintext, len, result, rlen);

    /* Final cleanup */
    BIO_free_all(bdec);

    return 1;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
