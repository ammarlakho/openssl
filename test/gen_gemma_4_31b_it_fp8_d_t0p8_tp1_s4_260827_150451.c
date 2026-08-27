/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p8_tp1_s4_260827_150451.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    int ok = 0;
    BIO *bmem = NULL, *benc = NULL;
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    unsigned char key[32], iv[16];
    const char *plain = "The quick brown fox jumps over the lazy dog";
    int plain_len = (int)strlen(plain);
    unsigned char decrypted[128];
    int read_len;
    char *ct_ptr = NULL;
    long ct_len;

    /* Fixed vectors for consistency */
    memset(key, 0x42, sizeof(key));
    memset(iv, 0x43, sizeof(iv));

    /* 1. Setup BIO chain: Cipher BIO -> Memory BIO */
    if (!TEST_ptr(bmem = BIO_new(BIO_s_mem())))
        goto err;

    if (!TEST_ptr(benc = BIO_push(BIO_f_cipher(), bmem)))
        goto err;

    /* 2. Encrypt phase */
    if (!TEST_true(BIO_set_cipher(benc, cipher, key, iv, 1)))
        goto err;

    if (!TEST_true(BIO_write(benc, plain, plain_len) == plain_len))
        goto err;

    /* Flush is critical to write the final block/padding */
    if (!TEST_true(BIO_ctrl(benc, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    /* Verify that ciphertext was actually produced and is not plaintext */
    ct_len = BIO_get_mem_data(bmem, &ct_ptr);
    if (!TEST_true(ct_len > 0))
        goto err;
    if (!TEST_true(memcmp(ct_ptr, plain, plain_len) != 0))
        goto err;

    /* 3. Decrypt phase */
    /* Reset the state for decryption using the same key/iv */
    if (!TEST_true(BIO_set_cipher(benc, cipher, key, iv, 0)))
        goto err;

    /* Reset memory BIO offset to read from the beginning of the ciphertext */
    BIO_set_mem_offset(bmem, 0);

    memset(decrypted, 0, sizeof(decrypted));
    read_len = BIO_read(benc, (char *)decrypted, sizeof(decrypted));
    if (!TEST_true(read_len == plain_len))
        goto err;

    if (!TEST_mem_eq(plain, plain_len, decrypted, read_len))
        goto err;

    ok = 1;

err:
    if (benc)
        BIO_free_all(benc);

    return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
