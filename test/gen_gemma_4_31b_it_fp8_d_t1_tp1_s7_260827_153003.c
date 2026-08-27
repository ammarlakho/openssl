/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t1_tp1_s7_260827_153003.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    BIO *bio_enc = NULL, *bio_mem_enc = NULL;
    BIO *bio_dec = NULL, *bio_mem_dec = NULL;
    unsigned char key[32], iv[16];
    const char *plaintext = "The quick brown fox jumps over the lazy dog";
    int pt_len = (int)strlen(plaintext);
    unsigned char ciphertext[128];
    unsigned char decrypted[128];
    int ct_len = 0, dt_len = 0;

    /* Set up fixed vectors for AES-256-CBC */
    memset(key, 0x01, sizeof(key));
    memset(iv, 0x02, sizeof(iv));

    /* 1. Encryption Path: BIO_f_cipher -> BIO_s_mem */
    bio_mem_enc = BIO_new(BIO_s_mem());
    if (!TEST_ptr(bio_mem_enc))
        goto err;

    bio_enc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bio_enc))
        goto err;

    if (!TEST_true(BIO_push(bio_enc, bio_mem_enc)))
        goto err;

    if (!TEST_true(BIO_set_cipher(bio_enc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    /* Write plaintext and flush to ensure padding is processed */
    if (!TEST_true(BIO_write(bio_enc, plaintext, pt_len) == pt_len))
        goto err;

    if (!TEST_true(BIO_ctrl(bio_enc, BIO_CTRL_FLUSH, 0, NULL)) )
        goto err;

    /* Extract ciphertext from the memory BIO */
    ct_len = BIO_read(bio_mem_enc, (char *)ciphertext, sizeof(ciphertext));
    if (ct_len <= 0)
        goto err;

    /* 2. Decryption Path: BIO_f_cipher -> BIO_s_mem (buffer) */
    bio_mem_dec = BIO_new_mem_buf(ciphertext, ct_len);
    if (!TEST_ptr(bio_mem_dec))
        goto err;

    bio_dec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bio_dec))
        goto err;

    if (!TEST_true(BIO_push(bio_dec, bio_mem_dec)))
        goto err;

    if (!TEST_true(BIO_set_cipher(bio_dec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    /* Read decrypted data */
    dt_len = BIO_read(bio_dec, (char *)decrypted, sizeof(decrypted));
    if (dt_len != pt_len)
        goto err;

    /* Verify round-trip integrity */
    if (!TEST_mem_eq(plaintext, pt_len, decrypted, dt_len))
        goto err;

    ok = 1;

err:
    if (bio_enc)
        BIO_free_all(bio_enc);
    if (bio_dec)
        BIO_free_all(bio_dec);
    /* bio_mem_enc and bio_mem_dec are freed by BIO_free_all if pushed */
    
    return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
