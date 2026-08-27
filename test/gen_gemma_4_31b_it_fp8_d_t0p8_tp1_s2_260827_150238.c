/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p8_tp1_s2_260827_150238.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    unsigned char key[32] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                              0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                              0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20 };
    unsigned char iv[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    
    /* Use a size that exercises the internal buffering (ENC_MIN_CHUNK = 256) */
    unsigned char plaintext[1024];
    unsigned char ciphertext[2048];
    unsigned char decrypted[2048];
    int pt_len = 1024;
    int ct_len = 0;
    int dt_len = 0;

    memset(plaintext, 'A', pt_len);
    plaintext[0] = 'B';
    plaintext[pt_len - 1] = 'C';

    /* --- Encryption Path --- */
    b_mem_enc = BIO_new(BIO_s_mem());
    if (!TEST_ptr(b_mem_enc))
        goto err;

    b_enc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(b_enc))
        goto err;

    if (!TEST_true(BIO_push(b_enc, b_mem_enc)))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_enc, cipher, key, iv, 1)))
        goto err;

    if (!TEST_true(BIO_write(b_enc, (char *)plaintext, pt_len) == pt_len))
        goto err;

    /* Flush is critical for padding */
    if (!TEST_true(BIO_ctrl(b_enc, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    /* Extract ciphertext from memory BIO */
    ct_len = BIO_read(b_mem_enc, (char *)ciphertext, sizeof(ciphertext));
    if (ct_len <= 0)
        goto err;

    /* --- Decryption Path --- */
    b_mem_dec = BIO_new(BIO_s_mem());
    if (!TEST_ptr(b_mem_dec))
        goto err;

    /* Write ciphertext into memory BIO so the cipher BIO can read it */
    if (!TEST_true(BIO_write(b_mem_dec, (char *)ciphertext, ct_len) == ct_len))
        goto err;

    b_dec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(b_dec))
        goto err;

    if (!TEST_true(BIO_push(b_dec, b_mem_dec)))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_dec, cipher, key, iv, 0)))
        goto err;

    /* Read back decrypted data */
    while ((dt_len += BIO_read(b_dec, (char *)decrypted + dt_len, sizeof(decrypted) - dt_len)) > 0);

    if (!TEST_true(dt_len == pt_len))
        goto err;

    if (!TEST_mem_eq(plaintext, pt_len, decrypted, dt_len))
        goto err;

    ok = 1;

err:
    if (b_enc) BIO_free_all(b_enc);
    if (b_dec) BIO_free_all(b_dec);
    /* b_mem_enc and b_mem_dec are freed by BIO_free_all on the chain */
    return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
