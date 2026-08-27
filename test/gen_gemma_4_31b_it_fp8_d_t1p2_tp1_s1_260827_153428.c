/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t1p2_tp1_s1_260827_153428.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    BIO *c_bio = NULL, *m_bio = NULL, *chain = NULL;
    BIO *c_bio_dec = NULL, *m_bio_dec = NULL, *chain_dec = NULL;
    const char *plain = "The quick brown fox jumps over the lazy dog - Testing BIO_f_cipher";
    int plain_len = (int)strlen(plain);
    unsigned char key[32] = { 0 };
    unsigned char iv[16] = { 0 };
    unsigned char encrypted[256];
    unsigned char decrypted[256];
    int enc_len = 0, dec_len = 0;

    /* 1. Setup Encryption Chain: BIO_f_cipher -> BIO_s_mem */
    if (!TEST_ptr((c_bio = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_ptr((m_bio = BIO_new(BIO_s_mem()))))
        goto err;
    if (!TEST_ptr((chain = BIO_push(c_bio, m_bio))))
        goto err;

    /* Initialize as AES-256 CBC Encryption */
    if (!TEST_true(BIO_set_cipher(chain, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    /* Encrypt data */
    if (!TEST_true(BIO_write(chain, plain, plain_len) == plain_len))
        goto err;

    /* Flush to ensure EVP_CipherFinal is called and padding is written */
    if (!TEST_true(BIO_flush(chain)))
        goto err;

    /* Read the resulting ciphertext from the underlying memory BIO */
    enc_len = BIO_read(m_bio, encrypted, sizeof(encrypted));
    if (enc_len <= 0)
        goto err;

    /* 2. Setup Decryption Chain: BIO_f_cipher -> BIO_s_mem (containing ciphertext) */
    if (!TEST_ptr((m_bio_dec = BIO_new(BIO_s_mem()))))
        goto err;
    if (!TEST_true(BIO_write(m_bio_dec, encrypted, enc_len) == enc_len))
        goto err;

    if (!TEST_ptr((c_bio_dec = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_ptr((chain_dec = BIO_push(c_bio_dec, m_bio_dec))))
        goto err;

    /* Initialize as AES-256 CBC Decryption */
    if (!TEST_true(BIO_set_cipher(chain_dec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    /* Decrypt data */
    dec_len = BIO_read(chain_dec, decrypted, sizeof(decrypted));
    if (dec_len <= 0)
        goto err;

    /* Verify round-trip result */
    if (!TEST_mem_eq(plain, plain_len, decrypted, dec_len))
        goto err;

    ok = 1;

err:
    if (chain)
        BIO_free_all(chain);
    if (chain_dec)
        BIO_free_all(chain_dec);

    return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
