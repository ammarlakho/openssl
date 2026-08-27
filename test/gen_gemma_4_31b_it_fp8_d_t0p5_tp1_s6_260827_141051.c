/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p5_tp1_s6_260827_141051.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    BIO *b_mem = NULL, *b_enc = NULL, *b_dec = NULL;
    unsigned char key[32], iv[16];
    unsigned char plain[] = "The quick brown fox jumps over the lazy dog. BIO cipher test!";
    int plain_len = (int)sizeof(plain) - 1;
    unsigned char ciphertext[1024];
    unsigned char decrypted[1024];
    int ct_len = 0, pt_len = 0;

    /* Initialize key and IV */
    memset(key, 0x42, sizeof(key));
    memset(iv, 0x24, sizeof(iv));

    /* 1. Setup Encryption Chain: BIO_f_cipher -> BIO_s_mem */
    if (!TEST_ptr((b_mem = BIO_new(BIO_s_mem()))))
        goto err;
    if (!TEST_ptr((b_enc = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_true(BIO_push(b_enc, b_mem)))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_enc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    /* Write plaintext and flush to ensure padding is processed */
    if (!TEST_true(BIO_write(b_enc, plain, plain_len) == plain_len))
        goto err;
    if (!TEST_true(BIO_ctrl(b_enc, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    /* Extract ciphertext from the memory BIO */
    ct_len = BIO_read(b_mem, ciphertext, sizeof(ciphertext));
    if (!TEST_true(ct_len > 0))
        goto err;

    /* Detach the encryption filter to reuse the memory BIO */
    if (!TEST_true(BIO_pop(b_enc, b_mem)))
        goto err;
    BIO_free(b_enc);
    b_enc = NULL;

    /* 2. Setup Decryption Chain: BIO_f_cipher -> BIO_s_mem (with ciphertext) */
    BIO_set_mem_offset(b_mem, 0);
    if (!TEST_ptr((b_dec = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_true(BIO_push(b_dec, b_mem)))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_dec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    /* Read from the cipher BIO to decrypt */
    pt_len = BIO_read(b_dec, decrypted, sizeof(decrypted));
    if (!TEST_true(pt_len == plain_len))
        goto err;

    if (!TEST_mem_eq(plain, plain_len, decrypted, pt_len))
        goto err;

    ok = 1;

err:
    if (b_enc) BIO_free_all(b_enc);
    if (b_dec) BIO_free_all(b_dec);
    if (b_mem && !b_dec) BIO_free(b_mem); /* b_dec free_all handles b_mem if pushed */

    return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
