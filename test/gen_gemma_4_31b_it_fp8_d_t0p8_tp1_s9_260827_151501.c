/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p8_tp1_s9_260827_151501.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    unsigned char pt[] = "OpenSSL BIO Cipher Round-trip Test Vector";
    int pt_len = (int)strlen((char *)pt);
    unsigned char key[32], iv[16];
    unsigned char ct[256];
    unsigned char decrypted[256];
    int ct_len = 0, dec_len = 0;
    BIO *b_enc = NULL, *b_mem_out = NULL;
    BIO *b_dec = NULL, *b_mem_in = NULL;

    /* Use fixed keys/iv for reproducibility */
    memset(key, 0x42, sizeof(key));
    memset(iv, 0x13, sizeof(iv));

    /* 
     * Encryption Path: 
     * BIO_f_cipher -> BIO_s_mem
     */
    if (!TEST_ptr(b_enc = BIO_new(BIO_f_cipher())))
        goto err;
    if (!TEST_ptr(b_mem_out = BIO_new(BIO_s_mem())))
        goto err;
    if (!TEST_true(BIO_push(b_enc, b_mem_out)))
        goto err;
    if (!TEST_true(BIO_set_cipher(b_enc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (!TEST_true(BIO_write(b_enc, pt, pt_len) == pt_len))
        goto err;
    /* Flush is required to process the final block (padding) */
    if (!TEST_true(BIO_ctrl(b_enc, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    /* Read the encrypted result from the memory BIO */
    ct_len = BIO_read(b_mem_out, ct, sizeof(ct));
    if (ct_len <= 0)
        goto err;

    /* 
     * Decryption Path: 
     * BIO_f_cipher -> BIO_s_mem
     */
    if (!TEST_ptr(b_dec = BIO_new(BIO_f_cipher())))
        goto err;
    if (!TEST_ptr(b_mem_in = BIO_new(BIO_s_mem())))
        goto err;
    if (!TEST_true(BIO_push(b_dec, b_mem_in)))
        goto err;
    if (!TEST_true(BIO_set_cipher(b_dec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    /* Write the ciphertext into the source memory BIO */
    if (!TEST_true(BIO_write(b_mem_in, ct, ct_len) == ct_len))
        goto err;

    /* Read and decrypt */
    dec_len = BIO_read(b_dec, decrypted, sizeof(decrypted));
    if (dec_len < 0)
        goto err;

    /* Flush to handle the final decrypted block */
    if (!TEST_true(BIO_ctrl(b_dec, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    int final_read = BIO_read(b_dec, decrypted + dec_len, sizeof(decrypted) - dec_len);
    if (final_read < 0)
        goto err;
    dec_len += final_read;

    /* Verify round-trip integrity */
    if (!TEST_mem_eq(pt, pt_len, decrypted, dec_len))
        goto err;

    BIO_free_all(b_enc);
    BIO_free_all(b_dec);
    return 1;

err:
    BIO_free_all(b_enc);
    BIO_free_all(b_dec);
    return 0;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
