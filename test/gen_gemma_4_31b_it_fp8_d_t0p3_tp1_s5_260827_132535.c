/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p3_tp1_s5_260827_132535.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    BIO *b_enc = NULL, *b_mem = NULL;
    BIO *b_dec = NULL, *b_mem_in = NULL;
    unsigned char key[32] = { 0 };
    unsigned char iv[16] = { 0 };
    unsigned char pt[] = "The quick brown fox jumps over the lazy dog";
    int pt_len = (int)strlen((char *)pt);
    unsigned char *ct_ptr = NULL;
    int ct_len = 0;
    unsigned char decrypted[256];
    int dec_len = 0;
    int ret = 0;

    /* 
     * Encryption Path:
     * BIO_f_cipher -> BIO_s_mem
     */
    if (!TEST_ptr((b_enc = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_ptr((b_mem = BIO_new(BIO_s_mem()))))
        goto err;
    if (!TEST_ptr(BIO_push(b_enc, b_mem)))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_enc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (!TEST_true(BIO_write(b_enc, pt, pt_len) == pt_len))
        goto err;

    /* Flush to handle padding */
    if (!TEST_true(BIO_ctrl(b_enc, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    /* Extract ciphertext from memory BIO */
    if (!TEST_true(BIO_get_mem_data(b_mem, &ct_ptr)))
        goto err;
    ct_len = BIO_ctrl(b_mem, BIO_CTRL_PENDING, 0, NULL);
    if (ct_len <= 0)
        goto err;

    /* Verify that ciphertext is not just the plaintext */
    if (ct_len == pt_len && TEST_mem_eq(ct_ptr, ct_len, pt, pt_len))
        goto err;

    /* 
     * Decryption Path:
     * BIO_f_cipher -> BIO_s_mem (with ciphertext)
     */
    if (!TEST_ptr((b_dec = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_ptr((b_mem_in = BIO_new_mem_buf(ct_ptr, ct_len))))
        goto err;
    if (!TEST_ptr(BIO_push(b_dec, b_mem_in)))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_dec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    dec_len = BIO_read(b_dec, decrypted, sizeof(decrypted));
    if (dec_len <= 0)
        goto err;

    /* Final round-trip verification */
    if (!TEST_mem_eq(pt, pt_len, decrypted, dec_len))
        goto err;

    ret = 1;

err:
    BIO_free(b_enc);
    BIO_free(b_dec);
    return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
