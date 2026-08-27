/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t1_tp1_s9_260827_153213.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    BIO *b_enc = NULL, *b_mem_enc = NULL;
    BIO *b_dec = NULL, *b_mem_dec = NULL;
    unsigned char key[32], iv[16];
    unsigned char plaintext[] = "The quick brown fox jumps over the lazy dog. OpenSSL BIO Cipher Test!";
    int pllen = (int)strlen((char *)plaintext);
    unsigned char ciphertext[1024];
    unsigned char decrypted[1024];
    int ctlen = 0, dlen = 0;

    /* Prepare key and IV */
    memset(key, 0x01, sizeof(key));
    memset(iv, 0x02, sizeof(iv));

    /* 1. Encryption: Plaintext -> BIO_f_cipher -> BIO_s_mem */
    b_mem_enc = BIO_new(BIO_s_mem());
    if (!TEST_ptr(b_mem_enc))
        goto err;

    b_enc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(b_enc))
        goto err;

    if (!TEST_true(BIO_push(b_enc, b_mem_enc)))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_enc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (!TEST_true(BIO_write(b_enc, (char *)plaintext, pllen) > 0))
        goto err;

    /* Flush is critical to push the final block/padding */
    if (!TEST_true(BIO_ctrl(b_enc, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    ctlen = BIO_read(b_mem_enc, (char *)ciphertext, sizeof(ciphertext));
    if (ctlen <= 0)
        goto err;

    /* 2. Decryption: BIO_s_mem (containing ciphertext) -> BIO_f_cipher -> Output */
    b_mem_dec = BIO_new(BIO_s_mem());
    if (!TEST_ptr(b_mem_dec))
        goto err;

    /* Load the ciphertext into the memory BIO */
    if (!TEST_true(BIO_write(b_mem_dec, (char *)ciphertext, ctlen) > 0))
        goto err;

    b_dec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(b_dec))
        goto err;

    if (!TEST_true(BIO_push(b_dec, b_mem_dec)))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_dec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    /* Read from cipher BIO to decrypt */
    dlen = BIO_read(b_dec, (char *)decrypted, sizeof(decrypted));
    if (dlen <= 0)
        goto err;

    if (!TEST_mem_eq(plaintext, pllen, decrypted, dlen))
        goto err;

    ok = 1;

err:
    if (b_enc)
        BIO_free_all(b_enc);
    if (b_dec)
        BIO_free_all(b_dec);
    /* b_mem_enc and b_mem_dec are handled by BIO_free_all if pushed */
    return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
