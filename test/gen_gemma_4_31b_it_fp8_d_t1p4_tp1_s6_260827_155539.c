/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t1p4_tp1_s6_260827_155539.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    int ret = 0;
    BIO *b_enc = NULL, *b_mem_enc = NULL;
    BIO *b_dec = NULL, *b_mem_dec = NULL;
    unsigned char key[32], iv[16];
    unsigned char *ciphertext = NULL;
    unsigned char decrypted[128];
    const char *plaintext = "The quick brown fox jumps over the lazy dog to test BIO_f_cipher";
    int pt_len = (int)strlen(plaintext);
    int ct_len = 0;
    int dt_len = 0;

    /* Setup test vectors: 0x01 for key, 0x02 for iv */
    memset(key, 0x01, sizeof(key));
    memset(iv, 0x02, sizeof(iv));

    /* 1. Encryption phase: BIO_f_cipher -> BIO_s_mem */
    if (!TEST_ptr((b_enc = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_ptr((b_mem_enc = BIO_new(BIO_s_mem()))))
        goto err;
    if (!TEST_true(BIO_push(b_enc, b_mem_enc)))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_enc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (!TEST_true(BIO_write(b_enc, plaintext, pt_len) == pt_len))
        goto err;

    /* Flush is required to process EVP_CipherFinal_ex (block padding) */
    if (!TEST_true(BIO_ctrl(b_enc, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    /* Retrieve encrypted result from the memory BIO */
    ct_len = BIO_read(b_mem_enc, ciphertext = OPENSSL_malloc(pt_len + 32), pt_len + 32);
    if (ct_len <= 0)
        goto err;

    /* 2. Decryption phase: BIO_f_cipher -> BIO_s_mem (initialized with ciphertext) */
    if (!TEST_ptr((b_dec = BIO_new(BIO_f_cipher()))))
        goto err;
    /* BIO_new_mem_buf is simpler for source-side read tests */
    if (!TEST_ptr((b_mem_dec = BIO_new_mem_buf(ciphertext, ct_len, BIO_NOCLOSE))))
        goto err;
    if (!TEST_true(BIO_push(b_dec, b_mem_dec)))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_dec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    /* Read from filter BIO until completion */
    while ((dt_len = BIO_read(b_dec, decrypted + dt_len, sizeof(decrypted) - dt_len)) > 0);

    /* We don't check BIO_CTRL_FLUSH for read unless there is specifically 
     * something pending in the buffer; enc_read handles final block when 
     * BIO_read(next) returns 0 or error. */

    if (!TEST_mem_eq(plaintext, pt_len, decrypted, dt_len))
        goto err;

    ret = 1;

err:
    if (b_enc) BIO_free_all(b_enc);
    if (b_dec) BIO_free_all(b_dec);
    if (ciphertext) OPENSSL_free(ciphertext);
    return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
