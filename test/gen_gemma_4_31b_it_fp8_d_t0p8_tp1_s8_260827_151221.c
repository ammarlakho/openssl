/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p8_tp1_s8_260827_151221.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    unsigned char pt[] = "The quick brown fox jumps over the lazy dog";
    int pt_len = (int)sizeof(pt) - 1;
    unsigned char key[32], iv[16], out[128];
    BIO *b_mem_enc = NULL, *b_enc = NULL, *b_mem_dec = NULL, *b_dec = NULL;
    int ct_len, read_len = 0, n;
    char *ct_ptr;

    memset(key, 0x42, sizeof(key));
    memset(iv, 0x24, sizeof(iv));
    memset(out, 0, sizeof(out));

    /* --- Encryption Phase --- */
    if (!TEST_ptr((b_mem_enc = BIO_new(BIO_s_mem()))))
        goto err;
    if (!TEST_ptr((b_enc = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_true(BIO_push(b_enc, b_mem_enc)))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_enc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (!TEST_true(BIO_write(b_enc, (const char *)pt, pt_len) == pt_len))
        goto err;

    /* Flush to ensure padding and final block are written to b_mem_enc */
    if (!TEST_true(BIO_ctrl(b_enc, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    /* Get ciphertext data from memory BIO */
    ct_len = BIO_ctrl(b_mem_enc, BIO_CTRL_WPENDING, 0, NULL);
    if (ct_len <= 0)
        goto err;
    ct_ptr = BIO_get_mem_data(b_mem_enc);
    if (!TEST_ptr(ct_ptr))
        goto err;

    /* Clean up encryption chain; b_mem_enc is freed by BIO_free_all(b_enc) */
    BIO_free_all(b_enc);
    b_enc = NULL;

    /* --- Decryption Phase --- */
    if (!TEST_ptr((b_mem_dec = BIO_new_mem_buf(ct_ptr, ct_len))))
        goto err;
    if (!TEST_ptr((b_dec = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_true(BIO_push(b_dec, b_mem_dec)))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_dec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    /* Read decrypted data back */
    while (read_len < pt_len && (n = BIO_read(b_dec, (char *)out + read_len, pt_len - read_len)) > 0) {
        read_len += n;
    }

    BIO_free_all(b_dec);

    /* Final verification: decrypted data must match original plaintext */
    return TEST_mem_eq(pt, pt_len, out, read_len);

err:
    if (b_enc) BIO_free_all(b_enc);
    if (b_dec) BIO_free_all(b_dec);
    return 0;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
