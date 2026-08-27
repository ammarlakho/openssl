/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t1_tp1_s5_260827_152612.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    unsigned char key[32] = "01234567890123456789012345678901";
    unsigned char iv[16] = "0123456789012345";
    const char *plaintext = "The quick brown fox jumps over the lazy dog";
    int pt_len = (int)strlen(plaintext);
    unsigned char ciphertext[128];
    unsigned char decrypted[128];
    int ct_len = 0, dt_len = 0;
    BIO *b_enc = NULL, *b_dec = NULL, *b_mem = NULL;

    /* 1. Encryption Phase: PT -> Cipher BIO -> Memory BIO */
    b_mem = BIO_new(BIO_s_mem());
    if (!TEST_ptr(b_mem))
        return 0;

    b_enc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(b_enc))
        goto err;

    if (!TEST_true(BIO_push(b_enc, b_mem)))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_enc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (!TEST_true(BIO_write(b_enc, plaintext, pt_len) > 0))
        goto err;

    /* Flush is mandatory to process final block/padding */
    if (!TEST_true(BIO_flush(b_enc)))
        goto err;

    /* Read ciphertext from the underlying memory BIO */
    ct_len = BIO_read(b_mem, ciphertext, sizeof(ciphertext));
    if (ct_len <= 0)
        goto err;

    /* Now we have the ciphertext. We verify the round-trip by decrypting. */

    /* 2. Decryption Phase: Memory BIO (with CT) -> Cipher BIO -> Output */
    /* We use a fresh memory BIO containing the ciphertext */
    BIO *b_mem_dec = BIO_new_mem_buf(ciphertext, ct_len);
    if (!TEST_ptr(b_mem_dec))
        goto err;

    b_dec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(b_dec))
        goto err;

    if (!TEST_true(BIO_push(b_dec, b_mem_dec)))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_dec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    /* Read back the plaintext */
    dt_len = BIO_read(b_dec, decrypted, sizeof(decrypted));
    if (dt_len <= 0)
        goto err;

    /* Verify result matches original plaintext */
    if (!TEST_mem_eq(plaintext, pt_len, decrypted, dt_len))
        goto err;

    BIO_free_all(b_enc);
    BIO_free_all(b_dec);
    return 1;

err:
    if (b_enc) BIO_free_all(b_enc);
    if (b_dec) BIO_free_all(b_dec);
    if (b_mem) BIO_free(b_mem);
    return 0;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
