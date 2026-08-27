/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p3_tp1_s1_260827_131841.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    BIO *bmem = NULL, *bcipher = NULL;
    unsigned char key[32], iv[16];
    const char *plain = "The quick brown fox jumps over the lazy dog";
    int plain_len = (int)strlen(plain);
    unsigned char cipher_buf[256], dec_buf[256];
    int cipher_len = 0, dec_len = 0;
    int ret;

    /* Initialize key and IV with fixed patterns */
    memset(key, 0x42, sizeof(key));
    memset(iv, 0x24, sizeof(iv));

    /* 1. Encryption Phase */
    bmem = BIO_new(BIO_s_mem());
    if (!TEST_ptr(bmem))
        return 0;

    bcipher = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bcipher)) {
        BIO_free(bmem);
        return 0;
    }

    if (!TEST_true(BIO_push(bcipher, bmem))) {
        BIO_free_all(bcipher);
        return 0;
    }

    if (!TEST_true(BIO_set_cipher(bcipher, EVP_aes_256_cbc(), key, iv, 1))) {
        BIO_free_all(bcipher);
        return 0;
    }

    ret = BIO_write(bcipher, plain, plain_len);
    if (!TEST_true(ret == plain_len)) {
        BIO_free_all(bcipher);
        return 0;
    }

    /* Flush to process padding and finalize encryption */
    if (!TEST_true(BIO_ctrl(bcipher, BIO_CTRL_FLUSH, 0, NULL))) {
        BIO_free_all(bcipher);
        return 0;
    }

    /* Extract ciphertext from the underlying memory BIO */
    cipher_len = BIO_read(bmem, cipher_buf, sizeof(cipher_buf));
    if (!TEST_true(cipher_len > 0)) {
        BIO_free_all(bcipher);
        return 0;
    }

    BIO_free_all(bcipher);

    /* 2. Decryption Phase */
    bmem = BIO_new_mem_buf(cipher_buf, cipher_len);
    if (!TEST_ptr(bmem))
        return 0;

    bcipher = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bcipher)) {
        BIO_free(bmem);
        return 0;
    }

    if (!TEST_true(BIO_push(bcipher, bmem))) {
        BIO_free_all(bcipher);
        return 0;
    }

    if (!TEST_true(BIO_set_cipher(bcipher, EVP_aes_256_cbc(), key, iv, 0))) {
        BIO_free_all(bcipher);
        return 0;
    }

    /* Read decrypted data. BIO_read on cipher BIO handles EVP_CipherFinal internally on EOF */
    dec_len = BIO_read(bcipher, dec_buf, sizeof(dec_buf));
    if (!TEST_true(dec_len == plain_len)) {
        BIO_free_all(bcipher);
        return 0;
    }

    /* Verify round-trip result */
    if (!TEST_mem_eq(plain, plain_len, dec_buf, dec_len)) {
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
