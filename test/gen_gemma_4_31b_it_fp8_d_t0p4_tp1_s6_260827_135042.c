/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p4_tp1_s6_260827_135042.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    BIO *b_enc = NULL, *b_mem = NULL, *b_dec = NULL, *b_mem_dec = NULL;
    unsigned char key[32], iv[16];
    unsigned char plain[] = "The quick brown fox jumps over the lazy dog";
    int plain_len = (int)strlen((char *)plain);
    unsigned char ciphertext[256];
    unsigned char decrypted[256];
    int enc_len = 0, dec_len = 0;

    memset(key, 0x01, sizeof(key));
    memset(iv, 0x02, sizeof(iv));

    /* --- Encryption Phase --- */
    if (!TEST_ptr((b_enc = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_ptr((b_mem = BIO_new(BIO_s_mem()))))
        goto err;
    if (!TEST_true(BIO_push(b_enc, b_mem)))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_enc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (!TEST_true(BIO_write(b_enc, plain, plain_len) == plain_len))
        goto err;

    /* Finalize encryption to push padding */
    if (!TEST_true(BIO_ctrl(b_enc, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    enc_len = BIO_read(b_mem, ciphertext, sizeof(ciphertext));
    if (enc_len <= 0)
        goto err;

    /* --- Decryption Phase --- */
    if (!TEST_ptr((b_mem_dec = BIO_new(BIO_s_mem()))))
        goto err;
    if (!TEST_true(BIO_write(b_mem_dec, ciphertext, enc_len) == enc_len))
        goto err;
    
    /* Reset read pointer of memory BIO to start */
    if (!TEST_true(BIO_set_init(b_mem_dec, 1)))
        goto err;

    if (!TEST_ptr((b_dec = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_true(BIO_push(b_dec, b_mem_dec)))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_dec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    /* Read decrypted data */
    dec_len = BIO_read(b_dec, decrypted, sizeof(decrypted));
    if (dec_len < 0)
        goto err;

    /* Finalize decryption to process padding */
    if (!TEST_true(BIO_ctrl(b_dec, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    int extra = BIO_read(b_dec, decrypted + dec_len, sizeof(decrypted) - dec_len);
    if (extra < 0)
        goto err;
    dec_len += extra;

    /* Verify round-trip */
    if (!TEST_mem_eq(plain, plain_len, decrypted, dec_len))
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
