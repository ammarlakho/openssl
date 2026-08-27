/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p6_tp1_s3_260827_142438.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    unsigned char key[32] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                              0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                              0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20 };
    unsigned char iv[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const char *plaintext = "The quick brown fox jumps over the lazy dog. BIO cipher test.";
    int plaintext_len = (int)strlen(plaintext);
    unsigned char decrypted[256];
    int read_len;
    BIO *bmem = NULL, *bcipher = NULL, *bchain = NULL;

    /* 1. Setup: Cipher BIO -> Memory BIO */
    if (!TEST_ptr((bmem = BIO_new(BIO_s_mem()))))
        return 0;
    if (!TEST_ptr((bcipher = BIO_new(BIO_f_cipher())))) {
        BIO_free(bmem);
        return 0;
    }
    bchain = BIO_push(bcipher, bmem);
    if (!TEST_ptr(bchain)) {
        BIO_free_all(bcipher);
        return 0;
    }

    /* 2. Encryption phase */
    if (!TEST_true(BIO_set_cipher(bchain, EVP_aes_256_cbc(), key, iv, 1))) {
        BIO_free_all(bchain);
        return 0;
    }

    if (!TEST_true(BIO_write(bchain, plaintext, plaintext_len) > 0)) {
        BIO_free_all(bchain);
        return 0;
    }

    /* Flush is critical to process EVP_CipherFinal_ex (padding) */
    if (!TEST_true(BIO_flush(bchain))) {
        BIO_free_all(bchain);
        return 0;
    }

    /* 3. Transition to Decryption */
    /* Reset the memory BIO read pointer to the beginning of the ciphertext */
    if (!TEST_true(BIO_reset(bmem))) {
        BIO_free_all(bchain);
        return 0;
    }

    /* Reconfigure the filter for decryption */
    if (!TEST_true(BIO_set_cipher(bchain, EVP_aes_256_cbc(), key, iv, 0))) {
        BIO_free_all(bchain);
        return 0;
    }

    /* 4. Decryption phase */
    memset(decrypted, 0, sizeof(decrypted));
    read_len = BIO_read(bchain, (char *)decrypted, sizeof(decrypted));
    if (read_len <= 0) {
        BIO_free_all(bchain);
        return 0;
    }

    /* 5. Verify round-trip result */
    if (!TEST_mem_eq(plaintext, plaintext_len, decrypted, read_len)) {
        BIO_free_all(bchain);
        return 0;
    }

    BIO_free_all(bchain);
    return 1;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
