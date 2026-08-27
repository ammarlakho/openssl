/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p5_tp1_s4_260827_140541.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    const char *plain = "The quick brown fox jumps over the lazy dog";
    int len = (int)strlen(plain);
    unsigned char key[32] = { 0x41 };
    unsigned char iv[16] = { 0x42 };
    unsigned char recovered[128];
    BIO *bmem = NULL, *bcipher = NULL;
    int ret = 0;

    /* 
     * Setup encryption chain: 
     * BIO_f_cipher (encrypt) -> BIO_s_mem 
     */
    bmem = BIO_new(BIO_s_mem());
    if (!TEST_ptr(bmem))
        return 0;

    bcipher = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bcipher)) {
        BIO_free(bmem);
        return 0;
    }
    BIO_push(bcipher, bmem);

    if (!TEST_true(BIO_set_cipher(bcipher, EVP_aes_256_cbc(), key, iv, 1))) {
        BIO_free_all(bcipher);
        return 0;
    }

    if (!TEST_true(BIO_write(bcipher, plain, len) == len)) {
        BIO_free_all(bcipher);
        return 0;
    }

    /* Flush to ensure padding is written to the memory BIO */
    if (!TEST_true(BIO_ctrl(bcipher, BIO_CTRL_FLUSH, 0, NULL) > 0)) {
        BIO_free_all(bcipher);
        return 0;
    }

    /* 
     * Free the encryption filter but keep the underlying memory BIO 
     * containing the ciphertext.
     */
    BIO_free(bcipher);
    bcipher = NULL;

    /* 
     * Setup decryption chain: 
     * BIO_f_cipher (decrypt) -> BIO_s_mem (containing ciphertext)
     */
    bcipher = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bcipher)) {
        BIO_free(bmem);
        return 0;
    }
    BIO_push(bcipher, bmem);

    if (!TEST_true(BIO_set_cipher(bcipher, EVP_aes_256_cbc(), key, iv, 0))) {
        BIO_free_all(bcipher);
        return 0;
    }

    /* Read back the decrypted plaintext */
    int rlen = BIO_read(bcipher, recovered, len);
    if (!TEST_true(rlen == len)) {
        BIO_free_all(bcipher);
        return 0;
    }

    /* Finalize decryption (process padding) */
    if (!TEST_true(BIO_ctrl(bcipher, BIO_CTRL_FLUSH, 0, NULL) > 0)) {
        BIO_free_all(bcipher);
        return 0;
    }

    /* Verify round-trip integrity */
    if (!TEST_mem_eq(plain, len, recovered, len)) {
        BIO_free_all(bcipher);
        return 0;
    }

    BIO_free_all(bcipher);
    return 1;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
