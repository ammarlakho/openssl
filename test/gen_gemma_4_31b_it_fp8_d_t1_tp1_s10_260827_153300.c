/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t1_tp1_s10_260827_153300.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    BIO *b_enc = NULL, *b_mem = NULL;
    BIO *b_dec = NULL, *b_mem_dec = NULL;
    unsigned char key[32] = { 0 };
    unsigned char iv[16] = { 0 };
    unsigned char plaintext[5000];
    unsigned char ciphertext[6000];
    unsigned char recovered[6000];
    int pt_len = 4999;
    int ct_len = 0;
    int rec_len = 0;

    /* 
     * We use a payload larger than ENC_BLOCK_SIZE (4096) and ENC_MIN_CHUNK (256)
     * to exercise the internal buffering and chunking logic in bio_enc.c
     */
    memset(plaintext, 'A', sizeof(plaintext));
    plaintext[pt_len - 1] = 'B';

    /* Setup encryption chain: BIO_f_cipher -> BIO_s_mem */
    b_mem = BIO_new(BIO_s_mem());
    if (!TEST_ptr(b_mem))
        goto err;

    b_enc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(b_enc))
        goto err;

    if (!TEST_true(BIO_push(b_enc, b_mem)))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_enc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    /* Write plaintext through the cipher BIO */
    if (!TEST_true(BIO_write(b_enc, (char *)plaintext, pt_len) == pt_len))
        goto err;

    /* Flush triggers EVP_CipherFinal_ex and pushes padding to the memory BIO */
    if (!TEST_true(BIO_ctrl(b_enc, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    /* Capture the ciphertext from the memory BIO */
    ct_len = BIO_read(b_mem, (char *)ciphertext, sizeof(ciphertext));
    if (!TEST_true(ct_len > pt_len)) /* Should be larger due to padding */
        goto err;

    /* Setup decryption chain: BIO_f_cipher -> BIO_s_mem */
    b_mem_dec = BIO_new(BIO_s_mem());
    if (!TEST_ptr(b_mem_dec))
        goto err;

    /* Load ciphertext into the memory BIO */
    if (!TEST_true(BIO_write(b_mem_dec, (char *)ciphertext, ct_len) == ct_len))
        goto err;

    b_dec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(b_dec))
        goto err;

    if (!TEST_true(BIO_push(b_dec, b_mem_dec)))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_dec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    /* Read decrypted data back */
    rec_len = BIO_read(b_dec, (char *)recovered, sizeof(recovered));
    if (!TEST_true(rec_len == pt_len))
        goto err;

    /* Verify round-trip integrity */
    if (!TEST_mem_eq(plaintext, pt_len, recovered, rec_len))
        goto err;

    ok = 1;

err:
    BIO_free_all(b_enc);
    BIO_free_all(b_dec);
    return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
